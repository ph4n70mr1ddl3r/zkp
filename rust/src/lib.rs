use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use k256::ecdsa::SigningKey;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::Coordinates;
use k256::FieldBytes;
use light_poseidon::{Poseidon, PoseidonHasher};
use lmdb::{Database, Transaction};
use sha3::{Digest, Keccak256};

/// Core library for ZK airdrop proof utilities.
///
/// This library provides functionality for:
/// - Merkle tree operations with Poseidon hashing
/// - Ethereum address handling and field element conversion
/// - ECDSA key parsing and address derivation
/// - LMDB database operations for Merkle tree storage
pub const ADDRESS_SIZE: usize = 20;
pub const FIELD_ELEMENT_SIZE: usize = 32;
pub const PRIVATE_KEY_HEX_SIZE: usize = 64;
pub const MAX_DBS: u32 = 4;

pub const DEFAULT_WORKER_COUNT: usize = 4;
pub const CHUNK_PAIRS: u64 = 200_000;
pub const DROP_DOMAIN: u64 = 1;

/// Computes the depth of a Merkle tree based on leaf count.
///
/// # Arguments
/// * `leaf_count` - The number of leaves in the tree
/// * `depth_meta` - The depth from metadata (used as fallback when leaf_count <= 1)
pub fn compute_tree_depth(leaf_count: usize, depth_meta: usize) -> usize {
    if leaf_count > 1 {
        (leaf_count - 1).ilog2() as usize + 1
    } else {
        depth_meta
    }
}

/// Stores Merkle tree metadata (leaf count and depth) to LMDB.
pub fn store_metadata_helper(
    env: &lmdb::Environment,
    meta_db: lmdb::Database,
    leaf_count: u64,
    depth: u32,
) -> Result<()> {
    let mut tx = env.begin_rw_txn()?;
    tx.put(
        meta_db,
        b"leaf_count",
        &leaf_count.to_be_bytes(),
        lmdb::WriteFlags::empty(),
    )?;
    tx.put(
        meta_db,
        b"depth",
        &depth.to_be_bytes(),
        lmdb::WriteFlags::empty(),
    )?;
    tx.commit()?;
    Ok(())
}

/// Returns the project root directory path.
pub fn project_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("failed to locate project root")
}

/// Reads a manifest file containing one filename per line and returns a list of paths.
pub fn read_manifest(path: &Path) -> Result<Vec<PathBuf>> {
    let file =
        File::open(path).with_context(|| format!("failed to open manifest {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        entries.push(path.parent().unwrap_or_else(|| Path::new("")).join(trimmed));
    }
    if entries.is_empty() {
        bail!("manifest {} is empty", path.display());
    }
    Ok(entries)
}

/// Finds the index of a target address across multiple shard files.
pub fn find_address_index(shard_files: &[PathBuf], target: &str) -> Result<usize> {
    let target = target.trim();
    let mut total = 0usize;
    for shard in shard_files {
        let file = File::open(shard)
            .with_context(|| format!("failed to open shard file {}", shard.display()))?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.eq_ignore_ascii_case(target) {
                return Ok(total);
            }
            total += 1;
        }
    }
    Err(anyhow!("address not found"))
}

/// Retrieves a Merkle tree node from the database at a given level and index.
pub fn get_node<T: Transaction>(tx: &T, db: Database, level: u32, idx: u64) -> Result<Fr> {
    let key = pack_key(level, idx);
    let bytes = tx.get(db, &key)?;
    bytes_to_fr(bytes)
}

/// Packs a level and index into a 12-byte key for LMDB storage.
pub fn pack_key(level: u32, idx: u64) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[..4].copy_from_slice(&level.to_be_bytes());
    buf[4..].copy_from_slice(&idx.to_be_bytes());
    buf
}

/// Converts a byte slice to a field element (Fr).
pub fn bytes_to_fr(bytes: &[u8]) -> Result<Fr> {
    ensure!(
        bytes.len() == FIELD_ELEMENT_SIZE,
        "expected {}-byte field element, got {}",
        FIELD_ELEMENT_SIZE,
        bytes.len()
    );
    let mut buf = [0u8; FIELD_ELEMENT_SIZE];
    buf.copy_from_slice(bytes);
    Ok(Fr::from_be_bytes_mod_order(&buf))
}

/// Converts a field element (Fr) to a byte vector.
pub fn fr_to_bytes(value: &Fr) -> Vec<u8> {
    value.into_bigint().to_bytes_be()
}

/// Parses a hex string into a field element (Fr).
pub fn fr_from_hex32(h: &str) -> Result<Fr> {
    let bytes = hex::decode(h).context("invalid hex")?;
    ensure!(
        bytes.len() == FIELD_ELEMENT_SIZE,
        "expected {}-byte hex",
        FIELD_ELEMENT_SIZE
    );
    let mut buf = [0u8; FIELD_ELEMENT_SIZE];
    buf.copy_from_slice(&bytes);
    Ok(Fr::from_be_bytes_mod_order(&buf))
}

/// Computes the hash of an Ethereum address using Poseidon.
pub fn hash_address(address_hex: &str, poseidon: &mut Poseidon<Fr>, zero_leaf: Fr) -> Result<Fr> {
    let leaf_scalar = address_to_field_element(address_hex)?;
    if leaf_scalar.is_zero() {
        Ok(zero_leaf)
    } else {
        hash_pair(poseidon, leaf_scalar, Fr::zero())
    }
}

fn address_to_field_element(address_hex: &str) -> Result<Fr> {
    let addr = address_hex.trim_start_matches("0x");
    let bytes = hex::decode(addr).with_context(|| format!("invalid hex address: {address_hex}"))?;
    if bytes.len() != ADDRESS_SIZE {
        bail!("address {} must be {} bytes", address_hex, ADDRESS_SIZE);
    }
    let mut padded = [0u8; FIELD_ELEMENT_SIZE];
    padded[FIELD_ELEMENT_SIZE - ADDRESS_SIZE..].copy_from_slice(&bytes);
    Ok(Fr::from_be_bytes_mod_order(&padded))
}

/// Hashes a pair of field elements using Poseidon.
pub fn hash_pair(poseidon: &mut Poseidon<Fr>, left: Fr, right: Fr) -> Result<Fr> {
    poseidon
        .hash(&[left, right])
        .map_err(|e| anyhow!(e.to_string()))
}

/// Computes the Poseidon hash of two field elements.
pub fn poseidon_hash2(a: Fr, b: Fr) -> Result<Fr> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    poseidon.hash(&[a, b]).map_err(|e| anyhow!(e.to_string()))
}

/// Derives the Ethereum address from an ECDSA verifying key.
pub fn eth_address(vk: &VerifyingKey) -> Result<String> {
    let point = vk.to_encoded_point(false);
    let coords = point.coordinates();
    let (x, y) = match coords {
        Coordinates::Uncompressed { x, y } => (x, y),
        _ => bail!("unexpected point encoding"),
    };
    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(x);
    encoded.extend_from_slice(y);
    let mut hasher = Keccak256::new();
    hasher.update(&encoded);
    let out = hasher.finalize();
    let addr = &out[12..];
    Ok(format!("0x{}", hex::encode(addr)))
}

/// Extracts the x and y coordinates of a public key as hex strings.
pub fn pubkey_hex(vk: &VerifyingKey) -> Result<(String, String)> {
    let point = vk.to_encoded_point(false);
    let coords = point.coordinates();
    let (x, y) = match coords {
        Coordinates::Uncompressed { x, y } => (x, y),
        _ => bail!("unexpected point encoding"),
    };
    Ok((hex::encode(x), hex::encode(y)))
}

/// Parses a hex string into a secp256k1 signing key.
pub fn parse_privkey(hex_key: &str) -> Result<SigningKey> {
    let trimmed = hex_key.strip_prefix("0x").unwrap_or(hex_key);
    if trimmed.len() != PRIVATE_KEY_HEX_SIZE {
        bail!(
            "private key must be 32-byte hex ({} hex chars), got {}",
            PRIVATE_KEY_HEX_SIZE,
            trimmed.len()
        );
    }
    let bytes = hex::decode(trimmed).context("invalid hex private key")?;
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("private key must be exactly 32 bytes"))?;
    let field_bytes: FieldBytes = raw.into();
    SigningKey::from_bytes(&field_bytes).map_err(|e| anyhow!("invalid secret key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_tree_depth() {
        assert_eq!(compute_tree_depth(0, 0), 0);
        assert_eq!(compute_tree_depth(1, 5), 5);
        assert_eq!(compute_tree_depth(2, 0), 1);
        assert_eq!(compute_tree_depth(3, 0), 2);
        assert_eq!(compute_tree_depth(4, 0), 2);
        assert_eq!(compute_tree_depth(5, 0), 3);
        assert_eq!(compute_tree_depth(8, 0), 3);
        assert_eq!(compute_tree_depth(16, 0), 4);
    }

    #[test]
    fn test_pack_key() {
        let key = pack_key(1, 100);
        assert_eq!(key.len(), 12);
        let level = u32::from_be_bytes(key[..4].try_into().unwrap());
        let idx = u64::from_be_bytes(key[4..].try_into().unwrap());
        assert_eq!(level, 1);
        assert_eq!(idx, 100);
    }

    #[test]
    fn test_fr_to_bytes_and_back() {
        let fr = Fr::from(42u64);
        let bytes = fr_to_bytes(&fr);
        let fr_back = bytes_to_fr(&bytes).unwrap();
        assert_eq!(fr, fr_back);
    }

    #[test]
    fn test_fr_from_hex32() {
        let hex_str = "000000000000000000000000000000000000000000000000000000000000002a";
        let fr = fr_from_hex32(hex_str).unwrap();
        assert_eq!(fr, Fr::from(42u64));
    }

    #[test]
    fn test_fr_from_hex32_invalid_length() {
        let hex_str = "2a";
        assert!(fr_from_hex32(hex_str).is_err());
    }

    #[test]
    fn test_address_to_field_element() {
        let addr = "0x1234567890123456789012345678901234567890";
        let fr = address_to_field_element(addr).unwrap();
        assert!(!fr.is_zero());
    }

    #[test]
    fn test_address_to_field_element_invalid() {
        let addr = "0x1234";
        assert!(address_to_field_element(addr).is_err());
    }

    #[test]
    fn test_poseidon_hash2() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let result = poseidon_hash2(a, b).unwrap();
        assert!(!result.is_zero());
    }

    #[test]
    fn test_parse_privkey() {
        let valid_key = "0000000000000000000000000000000000000000000000000000000000000001";
        let sk = parse_privkey(valid_key);
        assert!(sk.is_ok());
    }

    #[test]
    fn test_parse_privkey_with_prefix() {
        let valid_key = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let sk = parse_privkey(valid_key);
        assert!(sk.is_ok());
    }

    #[test]
    fn test_parse_privkey_invalid_length() {
        let invalid_key = "00000000000000000000000000000000000000000000000000000000000001";
        let sk = parse_privkey(invalid_key);
        assert!(sk.is_err());
    }

    #[test]
    fn test_hash_address() {
        let addr = "0x1234567890123456789012345678901234567890";
        let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
        let zero_leaf = Fr::zero();
        let hash = hash_address(addr, &mut poseidon, zero_leaf).unwrap();
        assert!(!hash.is_zero());
    }
}
