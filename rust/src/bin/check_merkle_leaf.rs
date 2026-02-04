use anyhow::{Context, Result};
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use clap::Parser;
use light_poseidon::Poseidon;
use lmdb::Environment;
use std::path::PathBuf;

use zkvote_proof::{find_address_index, get_node, hash_pair, project_root, read_manifest, MAX_DBS};

/// Look up a specific address in merkle.db and verify its leaf hash.
#[derive(Debug, Parser)]
#[command(name = "check-merkle-leaf")]
#[command(about = "Verify a single leaf stored in merkle.db")]
struct Args {
    /// Address to check (0x-prefixed, 20 bytes).
    address: String,
    /// Path to the shard manifest (one filename per line).
    #[arg(long, default_value = "shards/manifest.txt")]
    manifest: PathBuf,
    /// Path to the existing LMDB directory.
    #[arg(long, default_value = "merkle.db")]
    db: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = project_root()?;

    let manifest_path = root.join(&args.manifest);
    let db_path = root.join(&args.db);

    let shard_files = read_manifest(&manifest_path)?;
    let target_addr = args.address.trim();
    let idx = find_address_index(&shard_files, target_addr)
        .with_context(|| format!("address {target_addr} not found in shards"))?;

    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let zero_leaf = Fr::zero();
    let addr_hex = target_addr.trim_start_matches("0x");
    let bytes =
        hex::decode(addr_hex).with_context(|| format!("invalid hex address: {target_addr}"))?;
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&bytes);
    let leaf_scalar = Fr::from_be_bytes_mod_order(&padded);
    let expected = if leaf_scalar.is_zero() {
        zero_leaf
    } else {
        hash_pair(&mut poseidon, leaf_scalar, Fr::zero())?
    };

    let env = Environment::new()
        .set_max_dbs(MAX_DBS)
        .open(&db_path)
        .with_context(|| format!("failed to open lmdb env at {}", db_path.display()))?;
    let nodes_db = env
        .open_db(Some("nodes"))
        .context("failed to open nodes db")?;

    let read_tx = env.begin_ro_txn()?;
    let stored = get_node(&read_tx, nodes_db, 0, idx as u64)
        .with_context(|| format!("missing leaf at idx {idx}"))?;

    println!("Address: {target_addr}");
    println!("Leaf index: {idx}");
    println!("Expected leaf hash: {}", expected.into_bigint());
    println!("Stored leaf hash:   {}", stored.into_bigint());
    if expected == stored {
        println!("OK: stored hash matches Poseidon(address || 0).");
        Ok(())
    } else {
        anyhow::bail!("mismatch: stored leaf hash does not match recomputed hash");
    }
}
