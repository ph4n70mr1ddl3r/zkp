use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use ark_bn254::Fr;
use ark_ff::Zero;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use light_poseidon::{Poseidon, PoseidonHasher};
use lmdb::{Database, DatabaseFlags, Environment, Transaction, WriteFlags};
use std::sync::mpsc;
use std::thread;

use zk_airdrop::{
    compute_tree_depth, fr_to_bytes, get_node, hash_address, hash_pair, pack_key, project_root,
    read_manifest, store_metadata_helper, CHUNK_PAIRS, DEFAULT_WORKER_COUNT, MAX_DBS,
};

/// Build a Poseidon Merkle tree from the shard list into LMDB and write the root to disk.
#[derive(Debug, Parser)]
#[command(name = "build-merkle-db")]
#[command(about = "Create merkle.db (LMDB env) and merkleroot.txt from the shard address set")]
struct Args {
    /// Path to the shard manifest (one filename per line).
    #[arg(long, default_value = "shards/manifest.txt")]
    manifest: PathBuf,
    /// Output LMDB directory (will be recreated).
    #[arg(long, default_value = "merkle.db")]
    db: PathBuf,
    /// Output text file for the Merkle root (decimal string).
    #[arg(long, default_value = "merkleroot.txt")]
    root_out: PathBuf,
    /// LMDB map size in gigabytes.
    #[arg(long, default_value_t = 16)]
    map_size_gb: usize,
    /// Leaf insert batch size before committing.
    #[arg(long, default_value_t = 100_000)]
    batch: usize,
    /// Number of worker threads to hash (defaults to available parallelism).
    #[arg(long)]
    workers: Option<usize>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = project_root()?;

    let manifest_path = root.join(&args.manifest);
    let db_path = root.join(&args.db);
    let root_out_path = root.join(&args.root_out);

    println!("Project root: {}", root.display());
    println!("Manifest: {}", manifest_path.display());
    println!("DB dir: {}", db_path.display());
    println!("Root file: {}", root_out_path.display());

    remove_path(&db_path)?;
    remove_path(&root_out_path)?;
    fs::create_dir_all(&db_path)
        .with_context(|| format!("failed to create {}", db_path.display()))?;

    if args.map_size_gb == 0 {
        anyhow::bail!("map_size_gb must be greater than 0");
    }
    if args.map_size_gb > 1024 {
        anyhow::bail!("map_size_gb must not exceed 1024");
    }
    let map_size = args.map_size_gb * (1 << 30);
    let env = Environment::new()
        .set_max_dbs(MAX_DBS)
        .set_map_size(map_size)
        .open(&db_path)
        .with_context(|| format!("failed to open lmdb env at {}", db_path.display()))?;

    let nodes_db = env
        .create_db(Some("nodes"), DatabaseFlags::empty())
        .context("create nodes db")?;
    let meta_db = env
        .create_db(Some("meta"), DatabaseFlags::empty())
        .context("create meta db")?;

    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;

    let shard_files = read_manifest(&manifest_path)?;

    let zero_leaf = Fr::zero();
    let workers = args
        .workers
        .or_else(|| thread::available_parallelism().ok().map(|v| v.get()))
        .unwrap_or(DEFAULT_WORKER_COUNT);
    let mut leaf_count =
        ingest_leaves(&env, nodes_db, &shard_files, zero_leaf, args.batch, workers)
            .context("ingesting leaves")?;
    if leaf_count == 0 {
        anyhow::bail!("no addresses found in manifest {}", manifest_path.display());
    }

    let padded_leaves = leaf_count.next_power_of_two();
    if padded_leaves > leaf_count {
        println!(
            "Padding {} leaves up to next power of two ({})",
            leaf_count, padded_leaves
        );
        pad_zero_leaves(
            &env,
            nodes_db,
            leaf_count,
            padded_leaves,
            zero_leaf,
            args.batch,
        )?;
        leaf_count = padded_leaves;
    }

    let depth = compute_tree_depth(leaf_count, 0);
    let zero_hashes = compute_zero_hashes(&mut poseidon, zero_leaf, depth + 1)?;

    store_metadata(&env, meta_db, leaf_count as u64, depth as u32)?;

    let root_val = build_tree(&env, nodes_db, leaf_count as u64, &zero_hashes, workers)
        .context("building merkle tree")?;
    store_root(&env, meta_db, &root_val)?;
    fs::write(&root_out_path, root_val.to_string())
        .with_context(|| format!("failed to write {}", root_out_path.display()))?;

    println!("Merkle root: {}", root_val);
    println!("Stored in {}", root_out_path.display());
    Ok(())
}

fn remove_path(path: &PathBuf) -> Result<()> {
    if path.exists() {
        if path.is_dir() {
            fs::remove_dir_all(path)
                .with_context(|| format!("failed to remove existing dir {}", path.display()))?;
        } else {
            fs::remove_file(path)
                .with_context(|| format!("failed to remove existing file {}", path.display()))?;
        }
    }
    Ok(())
}

fn store_metadata(env: &Environment, meta_db: Database, leaf_count: u64, depth: u32) -> Result<()> {
    store_metadata_helper(env, meta_db, leaf_count, depth)
}

fn store_root(env: &Environment, meta_db: Database, root: &Fr) -> Result<()> {
    let mut tx = env.begin_rw_txn()?;
    tx.put(meta_db, b"root", &fr_to_bytes(root), WriteFlags::empty())?;
    tx.commit()?;
    Ok(())
}

fn ingest_leaves(
    env: &Environment,
    nodes_db: Database,
    shard_files: &[PathBuf],
    zero_leaf: Fr,
    batch: usize,
    workers: usize,
) -> Result<usize> {
    println!("Hashing leaves with Poseidon and writing level 0 to LMDB…");
    let mut total = 0usize;
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner} hashed {pos} leaves")
            .unwrap(),
    );

    let mut buffer = Vec::with_capacity(batch);
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
            buffer.push((total as u64, trimmed.to_string()));
            total += 1;

            if buffer.len() >= batch {
                hash_and_flush_leaves(env, nodes_db, &buffer, zero_leaf, workers)?;
                buffer.clear();
                pb.set_position(total as u64);
            }
        }
    }

    if !buffer.is_empty() {
        hash_and_flush_leaves(env, nodes_db, &buffer, zero_leaf, workers)?;
        buffer.clear();
    }

    pb.set_position(total as u64);
    pb.finish_with_message(format!("hashed {total} leaves"));
    Ok(total)
}

fn pad_zero_leaves(
    env: &Environment,
    nodes_db: Database,
    start: usize,
    end: usize,
    zero_leaf: Fr,
    batch: usize,
) -> Result<()> {
    let mut tx = env.begin_rw_txn()?;
    for idx in start..end {
        let key = pack_key(0, idx as u64);
        tx.put(
            nodes_db,
            &key,
            &fr_to_bytes(&zero_leaf),
            WriteFlags::empty(),
        )?;
        if (idx - start + 1).is_multiple_of(batch) {
            tx.commit()?;
            tx = env.begin_rw_txn()?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn compute_zero_hashes(
    poseidon: &mut Poseidon<Fr>,
    zero_leaf: Fr,
    levels: usize,
) -> Result<Vec<Fr>> {
    let mut zeros = Vec::with_capacity(levels);
    zeros.push(zero_leaf);
    for level in 1..levels {
        let prev = zeros[level - 1];
        let z = hash_pair(poseidon, prev, prev)?;
        zeros.push(z);
    }
    Ok(zeros)
}

fn build_tree(
    env: &Environment,
    nodes_db: Database,
    mut level_count: u64,
    zero_hashes: &[Fr],
    workers: usize,
) -> Result<Fr> {
    let mut level: u32 = 0;

    while level_count > 1 {
        let parent_level_count = level_count.div_ceil(2);
        println!(
            "Building level {} → {} ({} nodes)",
            level,
            level + 1,
            parent_level_count
        );
        let pb = ProgressBar::new(parent_level_count);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} parents")
                .unwrap(),
        );

        let read_tx = env.begin_ro_txn()?;
        let mut write_tx = env.begin_rw_txn()?;

        let mut start: u64 = 0;
        while start < parent_level_count {
            let end = (start + CHUNK_PAIRS).min(parent_level_count);
            let mut pairs = Vec::with_capacity((end - start) as usize);
            for parent_idx in start..end {
                let left =
                    get_node(&read_tx, nodes_db, level, parent_idx * 2).with_context(|| {
                        format!(
                            "missing left child at level {level}, idx {}",
                            parent_idx * 2
                        )
                    })?;

                let right_idx = parent_idx * 2 + 1;
                let right = if right_idx < level_count {
                    get_node(&read_tx, nodes_db, level, right_idx).with_context(|| {
                        format!("missing right child at level {level}, idx {right_idx}")
                    })?
                } else {
                    zero_hashes[level as usize]
                };
                pairs.push((parent_idx, left, right));
            }

            let hashed = parallel_hash_pairs(pairs, workers)?;
            for (parent_idx, parent) in hashed {
                let key = pack_key(level + 1, parent_idx);
                write_tx.put(nodes_db, &key, &fr_to_bytes(&parent), WriteFlags::empty())?;
                pb.inc(1);
            }

            start = end;
        }

        write_tx.commit()?;
        pb.finish();
        level_count = parent_level_count;
        level += 1;
    }

    let read_tx = env.begin_ro_txn()?;
    let root = get_node(&read_tx, nodes_db, level, 0).context("missing root after build")?;
    Ok(root)
}

fn hash_and_flush_leaves(
    env: &Environment,
    nodes_db: Database,
    buffer: &[(u64, String)],
    zero_leaf: Fr,
    workers: usize,
) -> Result<()> {
    let hashed = parallel_hash_leaves(buffer, zero_leaf, workers)?;
    let mut tx = env.begin_rw_txn()?;
    for (idx, leaf_hash) in hashed {
        let key = pack_key(0, idx);
        tx.put(
            nodes_db,
            &key,
            &fr_to_bytes(&leaf_hash),
            WriteFlags::empty(),
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn parallel_hash_leaves(
    chunk: &[(u64, String)],
    zero_leaf: Fr,
    workers: usize,
) -> Result<Vec<(u64, Fr)>> {
    if chunk.is_empty() {
        return Ok(Vec::new());
    }
    let threads = workers.max(1);
    let chunk_size = chunk.len().div_ceil(threads);
    let (tx, rx) = mpsc::channel();
    let (error_tx, error_rx) = mpsc::channel();

    thread::scope(|scope| {
        for slice in chunk.chunks(chunk_size) {
            let tx = tx.clone();
            let error_tx = error_tx.clone();
            scope.spawn(move || {
                let mut poseidon = Poseidon::<Fr>::new_circom(2).map_err(anyhow::Error::msg)?;
                let mut local = Vec::with_capacity(slice.len());
                for (idx, addr) in slice {
                    let leaf = hash_address(addr, &mut poseidon, zero_leaf).map_err(|e| {
                        let _ = error_tx.send(e.to_string());
                        anyhow::anyhow!("hash failed: {}", e)
                    })?;
                    local.push((*idx, leaf));
                }
                tx.send(local)?;
                Ok::<_, anyhow::Error>(())
            });
        }
    });

    drop(tx);
    drop(error_tx);

    if let Some(err_msg) = error_rx.try_iter().next() {
        return Err(anyhow::anyhow!("worker error: {}", err_msg));
    }

    let mut out: Vec<(u64, Fr)> = rx.into_iter().flatten().collect();
    out.sort_by_key(|(idx, _)| *idx);
    Ok(out)
}

fn parallel_hash_pairs(pairs: Vec<(u64, Fr, Fr)>, workers: usize) -> Result<Vec<(u64, Fr)>> {
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let threads = workers.max(1);
    let chunk_size = pairs.len().div_ceil(threads);
    let (tx, rx) = mpsc::channel();
    let (error_tx, error_rx) = mpsc::channel();

    thread::scope(|scope| {
        for slice in pairs.chunks(chunk_size) {
            let tx = tx.clone();
            let error_tx = error_tx.clone();
            let slice = slice.to_vec();
            scope.spawn(move || {
                let mut poseidon = Poseidon::<Fr>::new_circom(2).map_err(anyhow::Error::msg)?;
                let mut local = Vec::with_capacity(slice.len());
                for (idx, left, right) in slice {
                    let parent = poseidon.hash(&[left, right]).map_err(|e| {
                        let _ = error_tx.send(e.to_string());
                        anyhow::anyhow!("hash failed: {}", e)
                    })?;
                    local.push((idx, parent));
                }
                tx.send(local)?;
                Ok::<_, anyhow::Error>(())
            });
        }
    });

    drop(tx);
    drop(error_tx);

    if let Some(err_msg) = error_rx.try_iter().next() {
        return Err(anyhow::anyhow!("worker error: {}", err_msg));
    }

    let mut out: Vec<(u64, Fr)> = rx.into_iter().flatten().collect();
    out.sort_by_key(|(idx, _)| *idx);
    Ok(out)
}
