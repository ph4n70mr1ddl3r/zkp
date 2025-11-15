export type PoseidonFn = (inputs: bigint[]) => bigint;

export function packLimbs(limbs: bigint[], poseidon: PoseidonFn): bigint {
  return poseidon(limbs);
}

export function computeLeaf(pkXLimbs: bigint[], pkYLimbs: bigint[], poseidon: PoseidonFn): bigint {
  const xHash = packLimbs(pkXLimbs, poseidon);
  const yHash = packLimbs(pkYLimbs, poseidon);
  return poseidon([xHash, yHash]);
}

export function computeIdentitySecret(sigRLimbs: bigint[], sigSLimbs: bigint[], poseidon: PoseidonFn): bigint {
  const rPack = packLimbs(sigRLimbs, poseidon);
  const sPack = packLimbs(sigSLimbs, poseidon);
  return poseidon([rPack, sPack]);
}

export function computeNullifier(sigRLimbs: bigint[], sigSLimbs: bigint[], proposalId: bigint, poseidon: PoseidonFn): { identitySecret: bigint; nullifier: bigint } {
  const identitySecret = computeIdentitySecret(sigRLimbs, sigSLimbs, poseidon);
  const nullifier = poseidon([identitySecret, proposalId]);
  return { identitySecret, nullifier };
}
