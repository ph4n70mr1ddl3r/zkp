import path from "path";
import { fileURLToPath } from "url";
import { writeJSON } from "../lib/fs.js";
import { PROOF_PATH, PUBLIC_PATH } from "../lib/constants.js";
import { createVoteProof } from "../lib/prover.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");

const WASM_PATH = path.join(PROJECT_ROOT, "build", "zkvote_js", "zkvote.wasm");
const ZKEY_PATH = path.join(PROJECT_ROOT, "build", "zkvote_final.zkey");

async function main() {
  const walletIndex = parseInt(process.env.WALLET_INDEX ?? "0", 10);
  const proposalId = BigInt(process.env.PROPOSAL_ID ?? "1");
  const voteChoice = BigInt(process.env.VOTE_CHOICE ?? "2");

  const result = await createVoteProof({ walletIndex, proposalId, voteChoice, wasmPath: WASM_PATH, zkeyPath: ZKEY_PATH });

  await writeJSON(PROOF_PATH, result.proof);
  await writeJSON(PUBLIC_PATH, result.publicSignals);

  console.log(`Proof written to ${PROOF_PATH}`);
  console.log(`Public signals written to ${PUBLIC_PATH}`);
  console.log(`Nullifier: ${result.nullifier.toString()}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
