# Anonymous ZK Voting Protocol

## Abstract
This repository defines the formal specification for an anonymous, eligibility-restricted voting protocol constructed from:
- Merkle commitments to public keys,
- ECDSA-derived identity secrets,
- Poseidon-based nullifiers,
- zk-SNARK proofs of ownership, membership, and uniqueness.

The system enforces strict one-vote-per-public-key-per-proposal while ensuring anonymity and requiring no registration phase.

## 1. Background
Most anonymous voting systems require:
- A trusted setup phase (registration),
- Per-voter identity issuance,
- Or explicit key binding before voting.

Option B avoids these requirements by deriving the voter's anonymous identity directly from a fixed-message ECDSA signature, enabling immediate voting after system deployment.

## 2. Eligibility Commitment
Eligible voters are represented by their secp256k1 public keys:
```
PK_i = (pk_x_i, pk_y_i)
leaf_i = Poseidon(pk_x_i, pk_y_i)
```
A Poseidon-based Merkle tree commits to the complete eligible voter set, and the verifier only stores:
```
root_pubkeys
```

## 3. Identity Secret
Each voter derives a secret identity via:
```
ID_MSG = keccak256("zkVote identity v1")
sig = ECDSA_sign(sk, ID_MSG)
identity_secret = Poseidon(sig_r, sig_s)
```
The signature remains private and is used only inside the SNARK witness.

## 4. Nullifier Formation
To ensure one-vote-per-public-key-per-proposal:
```
nullifier = Poseidon(identity_secret, proposalId)
```
This yields deterministic nullifiers for repeated voting attempts, while preserving unlinkability to the public key.

## 5. zk-SNARK Statement
The SNARK must enforce:

1. **Key Ownership**
```
VerifyECDSA(PK, ID_MSG, sig) = 1
```

2. **Merkle Membership**
```
leaf = Poseidon(pk_x, pk_y)
MerkleVerify(root_pubkeys, leaf, path) = 1
```

3. **Identity Derivation**
```
identity_secret = Poseidon(sig_r, sig_s)
```

4. **Nullifier Correctness**
```
nullifier = Poseidon(identity_secret, proposalId)
```

All secret values `(pk, sig, identity_secret, path)` remain hidden.

## 6. Verification Logic
Verifiers (e.g., smart contracts) perform:
1. SNARK verification  
2. Nullifier uniqueness check:
```
if usedNullifier[proposalId][nullifier] == true: reject  
else: accept and record nullifier
```

## 7. Security Model
The protocol achieves:
- **Anonymity** through zero-knowledge,
- **Eligibility** via Merkle commitments,
- **Ownership** via in-circuit ECDSA verification,
- **Uniqueness** via nullifier enforcement,
- **Non-linkability** across proposals.

Security relies on:
- Soundness and zero-knowledge of the SNARK,
- Collision resistance of Poseidon,
- Unforgeability of ECDSA on secp256k1.

## 8. Repository Contents
- `SUMMARY.md` — High-level formal description  
- `CIRCUIT_SPEC.md` — Full zk circuit specification  
- Example scripts and implementation notes (to be added by developers)

This repository is intended for researchers and engineers building secure anonymous voting primitives.
