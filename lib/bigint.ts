export function toLimbs(value: bigint, limbBits = 64, limbCount = 4): bigint[] {
  const mask = (1n << BigInt(limbBits)) - 1n;
  const limbs: bigint[] = [];
  let remaining = value;
  for (let i = 0; i < limbCount; i++) {
    limbs.push(remaining & mask);
    remaining >>= BigInt(limbBits);
  }
  return limbs;
}

export function limbsToStrings(values: bigint[]): string[] {
  return values.map((v) => v.toString());
}
