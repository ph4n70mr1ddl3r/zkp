use anyhow::Context;
use ark_ff::PrimeField;
use lmdb::{Environment, Transaction};

use zk_airdrop::{bytes_to_fr, project_root, MAX_DBS};

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
    println!("leaf_count: {}", u64::from_be_bytes(leaf_count.try_into()?));
    println!("depth: {}", u32::from_be_bytes(depth.try_into()?));
    println!("root: {}", bytes_to_fr(root_bytes)?.into_bigint());
    Ok(())
}
