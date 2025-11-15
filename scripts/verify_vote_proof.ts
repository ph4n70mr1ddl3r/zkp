import path from "path";
import { fileURLToPath } from "url";
import { groth16 } from "snarkjs";
import { readJSON } from "../lib/fs.js";
import { PROOF_PATH, PUBLIC_PATH } from "../lib/constants.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");
const VK_PATH = path.join(PROJECT_ROOT, "build", "verification_key.json");

async function main() {
  const verificationKey = await readJSON(VK_PATH);
  const proof = await readJSON(PROOF_PATH);
  const publicSignals = await readJSON<string[]>(PUBLIC_PATH);

  const isValid = await groth16.verify(verificationKey, publicSignals, proof);
  console.log(`Verification result: ${isValid}`);
  if (!isValid) {
    process.exitCode = 1;
    return;
  }
  const [root, proposalId, nullifier, voteHash] = publicSignals;
  console.log(`root_pubkeys: ${root}`);
  console.log(`proposalId: ${proposalId}`);
  console.log(`nullifier: ${nullifier}`);
  console.log(`voteHash: ${voteHash}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
