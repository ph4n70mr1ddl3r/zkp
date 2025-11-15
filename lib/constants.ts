export const MERKLE_DEPTH = 4; // Supports up to 16 voters
export const NUM_WALLETS = 8;
export const LIMB_BITS = 64;
export const LIMB_COUNT = 4;
export const IDENTITY_MESSAGE = "zkVote identity v1";
export const IDENTITY_MESSAGE_HASH = "0xfe5ab79b940cd09c8768f2b1e78c9ae1952ccedb74cdca4f58e259eb5d1533e8";
export const IDENTITY_MESSAGE_LIMBS = [
  6404780487488123880n,
  10749193852579334735n,
  9757315438606064353n,
  18328163512369336476n
];
export const DEFAULT_ZERO_VALUE = 0n;
export const DATA_DIR = new URL("../data/", import.meta.url).pathname;
export const PUBKEYS_PATH = new URL("../data/pubkeys.json", import.meta.url).pathname;
export const MERKLE_TREE_PATH = new URL("../data/merkle_tree.json", import.meta.url).pathname;
export const PROOF_PATH = new URL("../data/proof.json", import.meta.url).pathname;
export const PUBLIC_PATH = new URL("../data/public.json", import.meta.url).pathname;
