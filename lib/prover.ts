import { Wallet } from "ethers";
import { buildPoseidon } from "circomlibjs";
import { groth16 } from "snarkjs";
import {
  IDENTITY_MESSAGE_HASH,
  LIMB_BITS,
  LIMB_COUNT,
  MERKLE_DEPTH,
  MERKLE_TREE_PATH,
  PUBKEYS_PATH
} from "./constants.js";
import { readJSON } from "./fs.js";
import { PoseidonMerkleTree } from "./merkle.js";
import { toLimbs, limbsToStrings } from "./bigint.js";
import { computeLeaf, computeNullifier, PoseidonFn } from "./vote.js";

interface StoredWallet {
  privateKey: string;
  publicKey: {
    x: string;
    y: string;
  };
}

interface WalletFile {
  wallets: StoredWallet[];
}

interface MerkleFile {
  depth: number;
  zeroValue: string;
  leaves: string[];
}

export interface VoteProofConfig {
  walletIndex: number;
  proposalId: bigint;
  voteChoice: bigint;
  wasmPath: string;
  zkeyPath: string;
}

export interface VoteProofResult {
  proof: unknown;
  publicSignals: string[];
  nullifier: bigint;
  voteHash: bigint;
}

let cachedPoseidon: PoseidonFn | null = null;

async function getPoseidon(): Promise<PoseidonFn> {
  if (cachedPoseidon) return cachedPoseidon;
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  cachedPoseidon = (inputs: bigint[]) => F.toObject(poseidon(inputs));
  return cachedPoseidon;
}

export async function createVoteProof(config: VoteProofConfig): Promise<VoteProofResult> {
  const poseidon = await getPoseidon();
  const walletFile = await readJSON<WalletFile>(PUBKEYS_PATH);
  const merkleFile = await readJSON<MerkleFile>(MERKLE_TREE_PATH);

  if (config.walletIndex >= walletFile.wallets.length) {
    throw new Error(`Wallet index ${config.walletIndex} exceeds stored wallets`);
  }
  if (merkleFile.depth !== MERKLE_DEPTH) {
    throw new Error("Merkle depth mismatch between config and stored tree");
  }

  const stored = walletFile.wallets[config.walletIndex];
  const wallet = new Wallet(stored.privateKey);
  const x = BigInt(stored.publicKey.x);
  const y = BigInt(stored.publicKey.y);
  const xLimbs = toLimbs(x, LIMB_BITS, LIMB_COUNT);
  const yLimbs = toLimbs(y, LIMB_BITS, LIMB_COUNT);
  const leaf = computeLeaf(xLimbs, yLimbs, poseidon);

  const leaves = merkleFile.leaves.map((value) => BigInt(value));
  const tree = PoseidonMerkleTree.fromLeaves(poseidon, MERKLE_DEPTH, leaves, BigInt(merkleFile.zeroValue));
  const leafIndex = leaves.findIndex((candidate) => candidate === leaf);
  if (leafIndex === -1) {
    throw new Error("Selected wallet leaf not present in stored tree");
  }

  const proofData = tree.generateProof(leafIndex);
  const signature = wallet.signingKey.sign(IDENTITY_MESSAGE_HASH);
  const sigR = BigInt(signature.r);
  const sigS = BigInt(signature.s);
  const sigRLimbs = toLimbs(sigR, LIMB_BITS, LIMB_COUNT);
  const sigSLimbs = toLimbs(sigS, LIMB_BITS, LIMB_COUNT);
  const { nullifier } = computeNullifier(sigRLimbs, sigSLimbs, config.proposalId, poseidon);
  const voteHash = poseidon([config.voteChoice]);

  const witnessInput = {
    root_pubkeys: tree.root.toString(),
    proposalId: config.proposalId.toString(),
    nullifier: nullifier.toString(),
    voteHash: voteHash.toString(),
    pk_x_limbs: limbsToStrings(xLimbs),
    pk_y_limbs: limbsToStrings(yLimbs),
    sig_r_limbs: limbsToStrings(sigRLimbs),
    sig_s_limbs: limbsToStrings(sigSLimbs),
    merkle_siblings: proofData.siblings.map((sibling) => sibling.toString()),
    merkle_pos: proofData.pathIndices
  };

  const { proof, publicSignals } = await groth16.fullProve(witnessInput, config.wasmPath, config.zkeyPath);

  return { proof, publicSignals: publicSignals.map(String), nullifier, voteHash };
}
