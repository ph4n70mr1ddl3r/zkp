use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::Coordinates;
use light_poseidon::{Poseidon, PoseidonHasher};
use lmdb::{Database, Transaction};
use sha3::{Digest, Keccak256};

pub const ADDRESS_SIZE: usize = 20;
pub const FIELD_ELEMENT_SIZE: usize = 32;
pub const PRIVATE_KEY_HEX_SIZE: usize = 64;
pub const MAX_DBS: u32 = 4;

pub fn compute_tree_depth(leaf_count: usize, depth_meta: usize) -> usize {
    if leaf_count > 1 {
        (leaf_count - 1).ilog2() as usize + 1
    } else {
        depth_meta
    }
}

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

pub fn project_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("failed to locate project root")
}

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

pub fn get_node<T: Transaction>(tx: &T, db: Database, level: u32, idx: u64) -> Result<Fr> {
    let key = pack_key(level, idx);
    let bytes = tx.get(db, &key)?;
    bytes_to_fr(bytes)
}

pub fn pack_key(level: u32, idx: u64) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[..4].copy_from_slice(&level.to_be_bytes());
    buf[4..].copy_from_slice(&idx.to_be_bytes());
    buf
}

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

pub fn fr_to_bytes(value: &Fr) -> Vec<u8> {
    value.into_bigint().to_bytes_be()
}

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

pub fn hash_leaf(address_hex: &str, poseidon: &mut Poseidon<Fr>, zero_leaf: Fr) -> Result<Fr> {
    let addr = address_hex.trim_start_matches("0x");
    let bytes = hex::decode(addr).with_context(|| format!("invalid hex address: {address_hex}"))?;
    if bytes.len() != ADDRESS_SIZE {
        bail!("address {} must be {} bytes", address_hex, ADDRESS_SIZE);
    }
    let mut padded = [0u8; FIELD_ELEMENT_SIZE];
    padded[FIELD_ELEMENT_SIZE - ADDRESS_SIZE..].copy_from_slice(&bytes);
    let leaf_scalar = Fr::from_be_bytes_mod_order(&padded);
    if leaf_scalar.is_zero() {
        Ok(zero_leaf)
    } else {
        hash_pair(poseidon, leaf_scalar, Fr::zero())
    }
}

pub fn hash_pair(poseidon: &mut Poseidon<Fr>, left: Fr, right: Fr) -> Result<Fr> {
    poseidon
        .hash(&[left, right])
        .map_err(|e| anyhow!(e.to_string()))
}

pub fn poseidon_hash2(a: Fr, b: Fr) -> Result<Fr> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    poseidon.hash(&[a, b]).map_err(|e| anyhow!(e.to_string()))
}

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

pub fn pubkey_hex(vk: &VerifyingKey) -> Result<(String, String)> {
    let point = vk.to_encoded_point(false);
    let coords = point.coordinates();
    let (x, y) = match coords {
        Coordinates::Uncompressed { x, y } => (x, y),
        _ => bail!("unexpected point encoding"),
    };
    Ok((hex::encode(x), hex::encode(y)))
}

pub fn hash_address(address_hex: &str, poseidon: &mut Poseidon<Fr>, zero_leaf: Fr) -> Result<Fr> {
    let addr = address_hex.trim_start_matches("0x");
    let bytes = hex::decode(addr).with_context(|| format!("invalid hex address: {address_hex}"))?;
    if bytes.len() != ADDRESS_SIZE {
        bail!("address {} must be {} bytes", address_hex, ADDRESS_SIZE);
    }
    let mut padded = [0u8; FIELD_ELEMENT_SIZE];
    padded[FIELD_ELEMENT_SIZE - ADDRESS_SIZE..].copy_from_slice(&bytes);
    let leaf_scalar = Fr::from_be_bytes_mod_order(&padded);
    if leaf_scalar.is_zero() {
        Ok(zero_leaf)
    } else {
        poseidon
            .hash(&[leaf_scalar, Fr::zero()])
            .map_err(|e| anyhow!(e.to_string()))
    }
}
