declare module "circomlibjs" {
  export type PoseidonFn = {
    (inputs: readonly bigint[]): unknown;
    F: {
      toObject(value: unknown): bigint;
    };
  };

  export function buildPoseidon(): Promise<PoseidonFn>;
}

declare module "snarkjs" {
  export const groth16: {
    fullProve(
      inputs: Record<string, unknown>,
      wasmPath: string,
      zkeyPath: string
    ): Promise<{ proof: unknown; publicSignals: unknown[] }>;
    verify(verificationKey: unknown, publicSignals: unknown[], proof: unknown): Promise<boolean>;
  };
}
