# Anonymous Voting System
## 1. Scope
This document provides a formal summary of the Option B anonymous voting construction, built using Merkle commitments, ECDSA-derived identity secrets, and zk-SNARK–based membership and ownership proofs. The system provides strict voter eligibility, vote uniqueness per proposal, and maximal anonymity, without requiring a registration phase.

## 2. Entities and Parameters
- **G**: Base point of secp256k1.
- **q**: Scalar field order of secp256k1.
- **H_P**: Poseidon hash function (field-based).
- **H_K**: Keccak-256 hash, used only for the fixed identity message.
- **ID_MSG**: `H_K("zkVote identity v1")`, constant for all voters.
- **proposalId**: Public identifier for a given proposal/election.
- **root_pubkeys**: Merkle root committing to all eligible secp256k1 public keys.
- **voteChoice**: Private vote value that will be hashed inside the circuit.

## 3. Public Key Commitment
Each eligible public key `PK_i = (pk_x_i, pk_y_i)` is committed using a Poseidon leaf:
```
leaf_i = H_P(pk_x_i, pk_y_i)
```
The Merkle tree `T` built over all leaves yields:
```
root_pubkeys = MerkleRoot(T)
```

## 4. Identity Secret
Each voter computes a fixed-message ECDSA signature:
```
sig = Sign(sk, ID_MSG)
sig = (sig_r, sig_s)
```
The identity secret is defined as:
```
identity_secret = H_P(sig_r, sig_s)
```
The identity secret is never revealed.

## 5. Nullifier
To enforce one-vote-per-public-key-per-proposal:
```
nullifier = H_P(identity_secret, proposalId)
```

## 6. zk-SNARK Statement
The prover shows knowledge of `(pk_x, pk_y, sig_r, sig_s, path, voteChoice)` such that:
1. `VerifyECDSA(PK, ID_MSG, sig) = 1`
2. `leaf = H_P(pk_x, pk_y)`
3. `MerkleVerify(root_pubkeys, leaf, path) = 1`
4. `identity_secret = H_P(sig_r, sig_s)`
5. `nullifier = H_P(identity_secret, proposalId)`
6. `voteHash = H_P(voteChoice)`

The proof reveals no secret values.

## 7. Security Summary
- **Eligibility**: Merkle membership enforces inclusion.
- **Ownership**: ECDSA verification enforces control of `sk`.
- **Uniqueness**: Nullifier prevents double voting.
- **Anonymity**: All secret values remain hidden, and nullifiers cannot be linked to public keys.
- **Non-interactivity**: SNARK proofs enable one-shot verification.
- **Vote binding**: The public `voteHash` binds a private vote choice without revealing it.

The Option B construction is formally secure under standard assumptions of secp256k1 ECDSA unforgeability, collision resistance of Poseidon, and soundness/zero-knowledge of the SNARK system.
