type HashFn = (inputs: bigint[]) => bigint;

export interface MerkleProof {
  siblings: bigint[];
  pathIndices: number[];
}

export class PoseidonMerkleTree {
  public readonly layers: bigint[][];
  constructor(
    public readonly depth: number,
    private readonly hashFn: HashFn,
    public readonly zeroValue: bigint,
    layers: bigint[][]
  ) {
    this.layers = layers;
  }

  static fromLeaves(hashFn: HashFn, depth: number, leaves: bigint[], zeroValue = 0n): PoseidonMerkleTree {
    const size = 1 << depth;
    if (leaves.length > size) {
      throw new Error(`Too many leaves (${leaves.length}) for depth ${depth}`);
    }
    const padded = leaves.slice();
    while (padded.length < size) {
      padded.push(zeroValue);
    }
    const layers: bigint[][] = [padded];
    for (let level = 1; level <= depth; level++) {
      const prev = layers[level - 1];
      const next: bigint[] = [];
      for (let i = 0; i < prev.length; i += 2) {
        next.push(hashFn([prev[i], prev[i + 1]]));
      }
      layers.push(next);
    }
    return new PoseidonMerkleTree(depth, hashFn, zeroValue, layers);
  }

  get root(): bigint {
    return this.layers[this.layers.length - 1][0];
  }

  getLeaf(index: number): bigint {
    return this.layers[0][index];
  }

  generateProof(index: number): MerkleProof {
    if (index < 0 || index >= this.layers[0].length) {
      throw new Error(`Leaf index ${index} out of bounds`);
    }
    const siblings: bigint[] = [];
    const pathIndices: number[] = [];
    let idx = index;
    for (let level = 0; level < this.depth; level++) {
      const layer = this.layers[level];
      const isRight = idx % 2;
      const pairIndex = isRight ? idx - 1 : idx + 1;
      siblings.push(layer[pairIndex]);
      pathIndices.push(isRight);
      idx = Math.floor(idx / 2);
    }
    return { siblings, pathIndices };
  }

  toJSON() {
    return {
      depth: this.depth,
      zeroValue: this.zeroValue.toString(),
      leaves: this.layers[0].map((leaf) => leaf.toString()),
      layers: this.layers.map((layer) => layer.map((value) => value.toString())),
      root: this.root.toString()
    };
  }
}
