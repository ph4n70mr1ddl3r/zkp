# zk-SNARK Specification for Anonymous Voting

## 1. Introduction
This document specifies the zero-knowledge circuit used to enforce:
- public-key ownership,
- eligibility via Merkle membership,
- correct identity derivation via signature hashing,
- nullifier correctness for uniqueness.

The circuit is field-oriented and compatible with Groth16, Plonk, or other SNARK systems.

## 2. Preliminaries

### 2.1 Notation
- Field operations are over SNARK scalar field `F`.
- secp256k1 operations are verified through scalar/point gadgets.
- Poseidon parameters follow standard field instantiation.

### 2.2 Constants
```
ID_MSG = keccak256("zkVote identity v1")
root_pubkeys ∈ F
proposalId ∈ F
nullifier ∈ F
voteHash ∈ F
```

### 2.3 Public Key Encoding
Each public key is represented by affine coordinates:
```
PK = (pk_x, pk_y)
```
These are encoded as field elements in the circuit.

## 3. Circuit Inputs

### 3.1 Public Inputs
- `root_pubkeys`
- `proposalId`
- `nullifier`
- `voteHash`

### 3.2 Private Inputs (Witness)
- `pk_x`, `pk_y`
- `sig_r`, `sig_s`
- `merkle_siblings[0..D-1]`
- `merkle_pos[0..D-1]`

## 4. Circuit Constraints

### 4.1 ECDSA Verification
The circuit verifies:
```
VerifyECDSA(pk_x, pk_y, ID_MSG, sig_r, sig_s) = 1
```
This ensures ownership of the private key corresponding to `PK`.

### 4.2 Merkle Verification
Compute:
```
leaf = Poseidon(pk_x, pk_y)
```
Then iteratively reconstruct the Merkle root:
```
current = leaf
for i in 0..D-1:
    if merkle_pos[i] == 0:
        current = Poseidon(current, merkle_siblings[i])
    else:
        current = Poseidon(merkle_siblings[i], current)
```
Constraint:
```
current == root_pubkeys
```

### 4.3 Identity Secret Derivation
```
identity_secret = Poseidon(sig_r, sig_s)
```

### 4.4 Nullifier Constraint
```
computed_nullifier = Poseidon(identity_secret, proposalId)
computed_nullifier == nullifier
```

## 5. Zero-Knowledge and Soundness
The circuit ensures:
- No revelation of `(pk, sig, identity_secret, path)`.
- Soundness enforces correct linkage.
- Nullifier correctness enforces uniqueness without identity leakage.

## 6. Security Assumptions
The circuit's security relies on:
- Soundness of the SNARK proof system,
- Zero-knowledge property of the SNARK,
- Collision resistance of Poseidon,
- Unforgeability of ECDSA on secp256k1,
- Infeasibility of reversing the nullifier mapping.

## 7. Conclusion
This specification defines all required constraints for Option B anonymous voting. Implementations must ensure consistent hashing, correct field encoding, and strict handling of signature components and Merkle proofs.
