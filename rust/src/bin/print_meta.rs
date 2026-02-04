use anyhow::Context;
use ark_ff::PrimeField;
use lmdb::{Environment, Transaction};

use zk_airdrop::{bytes_to_fr, project_root, MAX_DBS};

fn bytes_to_u64(bytes: &[u8]) -> Result<u64, std::array::TryFromSliceError> {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(arr))
}

fn bytes_to_u32(bytes: &[u8]) -> Result<u32, std::array::TryFromSliceError> {
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    Ok(u32::from_be_bytes(arr))
}

fn main() -> anyhow::Result<()> {
    let root = project_root()?;
    let db_path = root.join("merkle.db");
    let env = Environment::new()
        .set_max_dbs(MAX_DBS)
        .open(&db_path)
        .with_context(|| format!("failed to open lmdb at {}", db_path.display()))?;
    let meta_db = env.open_db(Some("meta"))?;
    let tx = env.begin_ro_txn()?;
    let leaf_count = tx.get(meta_db, b"leaf_count")?;
    let depth = tx.get(meta_db, b"depth")?;
    let root_bytes = tx.get(meta_db, b"root")?;
    println!("leaf_count: {}", bytes_to_u64(leaf_count)?);
    println!("depth: {}", bytes_to_u32(depth)?);
    println!("root: {}", bytes_to_fr(root_bytes)?.into_bigint());
    Ok(())
}
