# zkVote Demo

Minimal end-to-end anonymous voting flow that proves "Option B" from the prompt: voters sign a fixed identity message with secp256k1 ECDSA, derive a Poseidon-based nullifier, and prove in Circom that they control a public key in a Poseidon Merkle tree.

## How it works
- **Identity binding** – Every wallet signs `ID_MSG = keccak256("zkVote identity v1")`. The circuit verifies the ECDSA signature using a vendored secp256k1 gadget and hashes `(sig_r, sig_s)` (packed via Poseidon) to produce `identity_secret`.
- **Nullifier** – `nullifier = Poseidon(identity_secret, proposalId)` is a public signal. The application rejects any vote that reuses a nullifier for the same proposal.
- **Membership proof** – Public keys are encoded as 4×64-bit limbs per coordinate (needed because secp256k1 elements exceed the BN254 field) and hashed into a Poseidon Merkle tree. The circuit recomputes the path and enforces `root_pubkeys`.
- **Vote binding** – `voteHash` is a public signal included in the transcript; higher layers decide how to interpret it.

```
.
├── circuits/
│   ├── vendor/circom-ecdsa/        # Persona Labs zk-ecdsa circuits (GPLv3)
│   ├── vendor/circomlib/           # Minimal circomlib subset (Poseidon, utils)
│   └── zkvote.circom               # Main circuit (depth 4, 4×64-bit limbs)
├── data/                           # Generated keys, tree, proofs
├── scripts/                        # TS drivers: tree, prove, verify, demo
└── lib/                            # Shared helpers (Poseidon, Merkle, limbs)
```

## Prerequisites
- Node.js 18+
- `circom` v2 and `snarkjs`
- `powersOfTau28_hez_final_22.ptau` downloaded to the project root (the setup script looks for `./powersOfTau28_hez_final_22.ptau`)

## Install & compile
```bash
npm install
npm run build:circom              # produces build/zkvote.r1cs + wasm
npm run setup:groth16             # runs Groth16 setup & creates verification key
```

## Generate sample voters & Merkle tree
```bash
npm run build:tree
```
- Creates `data/pubkeys.json` with 8 random wallets (index, address, private key, limbs).
- Builds a Poseidon Merkle tree (depth 4) over hashed keys and stores it in `data/merkle_tree.json`.

## Produce a vote proof
```bash
npm run prove
```
- Uses wallet index `0` (`WALLET_INDEX` env var overrides it), `proposalId = 1` (`PROPOSAL_ID`) and `voteChoice = 2` (`VOTE_CHOICE`).
- Signs the fixed identity message, derives the nullifier, constructs the Merkle path, and calls `snarkjs.groth16.fullProve` with `build/zkvote_js/zkvote.wasm` + `build/zkvote_final.zkey`.
- Writes `data/proof.json` and `data/public.json`.

## Verify the proof
```bash
npm run verify
```
- Loads `build/verification_key.json`, `data/proof.json`, and `data/public.json` and prints the verification result plus the public signals (`root_pubkeys`, `proposalId`, `nullifier`, `voteHash`).

## Demonstrate nullifier reuse rejection
```bash
npm run demo:double-vote
```
- Generates two Groth16 proofs for the same wallet/proposal (different `voteChoice`).
- Verifies both proofs and shows that both emit the same nullifier, so a simple `Set` catch repeats.

## Configuration
- Core parameters live in `lib/constants.ts` (`MERKLE_DEPTH`, `NUM_WALLETS`, limb encoding, identity message hash). Increase the depth or number of wallets as needed (remember to rebuild the circuit if you change the depth or limb settings).
- Scripts accept environment overrides:
  - `WALLET_INDEX` – which wallet to use.
  - `PROPOSAL_ID` – proposal identifier bound into the nullifier.
  - `VOTE_CHOICE` – integer that is Poseidon-hashed into `voteHash`.

## Circuit specifics (`circuits/zkvote.circom`)
- Parameterized template `ZKVote(DEPTH, LIMB_BITS, LIMB_COUNT)`; `main` instantiates `(4, 64, 4)` by default.
- Includes Persona Labs' secp256k1 ECDSA gadget (GPLv3) under `circuits/vendor/circom-ecdsa`.
- Packs limbs via Poseidon to stay in-field for hashing/identity derivation.
- Enforces boolean Merkle direction bits, ECDSA verification of the fixed message, and nullifier correctness.

## Data artifacts
`data/` is tracked with a `.gitkeep`; scripts overwrite:
- `pubkeys.json`
- `merkle_tree.json`
- `proof.json`
- `public.json`

## Third-party code
`circuits/vendor/circom-ecdsa` is copied from [Persona Labs' zk-ecdsa project](https://github.com/personaelabs/zk-ecdsa) and remains under GPLv3 (see `circuits/vendor/circom-ecdsa/THIRD_PARTY_LICENSE_GPLv3.txt`). `circuits/vendor/circomlib` contains the handful of circomlib gadgets required for this demo (Poseidon, bitify, comparators, etc.) and inherits circomlib's license. All other code in this repo is MIT-compatible (default npm behavior).

## Limitations
- Tree depth, sample size, and limb encoding are hardcoded for simplicity; change them and recompile before production use.
- Proof generation expects Groth16 artifacts in `./build`. Run `npm run build:circom` / `npm run setup:groth16` after every circuit change.
- This is a local demo. Real deployments must audit the circuits, randomness (entropy), and Groth16 trusted setup ceremony.
