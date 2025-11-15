import { Wallet } from "ethers";
import { buildPoseidon } from "circomlibjs";
import {
  DATA_DIR,
  DEFAULT_ZERO_VALUE,
  IDENTITY_MESSAGE,
  IDENTITY_MESSAGE_HASH,
  LIMB_BITS,
  LIMB_COUNT,
  MERKLE_DEPTH,
  NUM_WALLETS,
  PUBKEYS_PATH,
  MERKLE_TREE_PATH
} from "../lib/constants.js";
import { ensureDir, writeJSON } from "../lib/fs.js";
import { PoseidonMerkleTree } from "../lib/merkle.js";
import { toLimbs, limbsToStrings } from "../lib/bigint.js";
import { computeLeaf } from "../lib/vote.js";

interface StoredWallet {
  index: number;
  address: string;
  privateKey: string;
  publicKey: {
    x: string;
    y: string;
    xLimbs: string[];
    yLimbs: string[];
  };
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const poseidonHash = (inputs: bigint[]) => F.toObject(poseidon(inputs));

  const wallets: StoredWallet[] = [];
  const leaves: bigint[] = [];

  for (let i = 0; i < NUM_WALLETS; i++) {
    const wallet = Wallet.createRandom();
    const { x, y } = extractPublicKey(wallet.signingKey.publicKey);
    const xLimbs = toLimbs(x, LIMB_BITS, LIMB_COUNT);
    const yLimbs = toLimbs(y, LIMB_BITS, LIMB_COUNT);
    const leaf = computeLeaf(xLimbs, yLimbs, poseidonHash);

    wallets.push({
      index: i,
      address: wallet.address,
      privateKey: wallet.privateKey,
      publicKey: {
        x: x.toString(),
        y: y.toString(),
        xLimbs: limbsToStrings(xLimbs),
        yLimbs: limbsToStrings(yLimbs)
      }
    });
    leaves.push(leaf);
  }

  const tree = PoseidonMerkleTree.fromLeaves(poseidonHash, MERKLE_DEPTH, leaves, DEFAULT_ZERO_VALUE);

  await ensureDir(DATA_DIR);
  await writeJSON(PUBKEYS_PATH, {
    limbBits: LIMB_BITS,
    limbCount: LIMB_COUNT,
    merkleDepth: MERKLE_DEPTH,
    numWallets: NUM_WALLETS,
    identityMessage: IDENTITY_MESSAGE,
    identityMessageHash: IDENTITY_MESSAGE_HASH,
    wallets
  });
  await writeJSON(MERKLE_TREE_PATH, {
    ...tree.toJSON(),
    leafCount: 1 << MERKLE_DEPTH
  });

  console.log(`Generated ${NUM_WALLETS} wallets`);
  console.log(`Merkle root: ${tree.root.toString()}`);
}

function extractPublicKey(publicKey: string): { x: bigint; y: bigint } {
  const hex = publicKey.replace(/^0x/, "");
  if (!hex.startsWith("04")) {
    throw new Error("Only uncompressed secp256k1 public keys are supported");
  }
  const body = hex.slice(2);
  const xHex = "0x" + body.slice(0, 64);
  const yHex = "0x" + body.slice(64);
  return { x: BigInt(xHex), y: BigInt(yHex) };
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
