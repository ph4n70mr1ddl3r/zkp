import path from "path";
import { fileURLToPath } from "url";
import { groth16 } from "snarkjs";
import { createVoteProof } from "../lib/prover.js";
import { readJSON } from "../lib/fs.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");

const WASM_PATH = path.join(PROJECT_ROOT, "build", "zkvote_js", "zkvote.wasm");
const ZKEY_PATH = path.join(PROJECT_ROOT, "build", "zkvote_final.zkey");
const VK_PATH = path.join(PROJECT_ROOT, "build", "verification_key.json");

async function main() {
  const walletIndex = parseInt(process.env.WALLET_INDEX ?? "0", 10);
  const proposalId = BigInt(process.env.PROPOSAL_ID ?? "1");

  const verificationKey = await readJSON(VK_PATH);

  const first = await createVoteProof({ walletIndex, proposalId, voteChoice: 2n, wasmPath: WASM_PATH, zkeyPath: ZKEY_PATH });
  const second = await createVoteProof({ walletIndex, proposalId, voteChoice: 3n, wasmPath: WASM_PATH, zkeyPath: ZKEY_PATH });

  const validFirst = await groth16.verify(verificationKey, first.publicSignals, first.proof);
  const validSecond = await groth16.verify(verificationKey, second.publicSignals, second.proof);

  console.log(`First proof valid: ${validFirst}`);
  console.log(`Second proof valid: ${validSecond}`);

  const seenNullifiers = new Set<string>();
  for (const [idx, result] of [first, second].entries()) {
    const label = idx === 0 ? "Vote #1" : "Vote #2";
    const nullifierHex = result.nullifier.toString();
    console.log(`${label} nullifier: ${nullifierHex}`);
    console.log(`${label} voteHash: ${result.publicSignals[3]}`);
    if (seenNullifiers.has(nullifierHex)) {
      console.log(`${label} rejected: nullifier already seen.`);
    } else {
      seenNullifiers.add(nullifierHex);
      console.log(`${label} accepted.`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
