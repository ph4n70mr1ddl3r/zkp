use std::fs::{self};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use clap::Parser;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, VerifyingKey};
use light_poseidon::Poseidon;
use lmdb::{Database, Environment, Transaction};
use serde::Serialize;
use sha2::{Digest, Sha256};

use zk_airdrop::{
    bytes_to_fr, compute_tree_depth, eth_address, find_address_index, fr_from_hex32, get_node,
    hash_address, parse_privkey, poseidon_hash2, project_root, pubkey_hex, read_manifest,
    DROP_DOMAIN, MAX_DBS,
};

/// Simulated prover for the private airdrop: derives address, leaf, nullifier and Merkle path.
#[derive(Debug, Parser)]
#[command(name = "airdrop-prove-sim")]
#[command(about = "Generate a non-zk proof artifact for an address in merkle.db")]
struct Args {
    /// 32-byte hex private key (0x-prefixed or not).
    privkey: String,
    /// Message to sign (hashed with SHA-256).
    #[arg(long, default_value = "zk-airdrop-claim")]
    message: String,
    /// Optional recipient address (0x-prefixed). Defaults to the signer address.
    #[arg(long)]
    recipient: Option<String>,
    /// Path to the shard manifest (one filename per line).
    #[arg(long, default_value = "shards/manifest.txt")]
    manifest: PathBuf,
    /// Path to the LMDB directory.
    #[arg(long, default_value = "merkle.db")]
    db: PathBuf,
    /// Output JSON path.
    #[arg(long, default_value = "data/airdrop_proof_sim.json")]
    output: PathBuf,
}

#[derive(Serialize)]
struct ProofSim {
    message: String,
    message_sha256: String,
    address: String,
    recipient: String,
    pubkey: PubKey,
    signature: Sig,
    leaf_index: u64,
    leaf_hash: String,
    nullifier: String,
    root: String,
    merkle_path: Vec<String>,
    merkle_pos: Vec<u8>,
}

#[derive(Serialize)]
struct PubKey {
    x: String,
    y: String,
}

#[derive(Serialize)]
struct Sig {
    r: String,
    s: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let root = project_root()?;

    let manifest_path = root.join(&args.manifest);
    let db_path = root.join(&args.db);
    let output_path = root.join(&args.output);

    let sk = parse_privkey(&args.privkey)?;
    let vk = VerifyingKey::from(&sk);
    let (pk_x_hex, pk_y_hex) = pubkey_hex(&vk)?;
    let address = eth_address(&vk)?;
    let recipient = args.recipient.unwrap_or_else(|| address.clone());

    let mut sha = Sha256::new();
    sha.update(args.message.as_bytes());
    let msg_digest = sha.finalize();

    let sig: Signature = sk.sign_prehash(&msg_digest).map_err(|e| anyhow!(e))?;
    let sig_r_hex = hex::encode(sig.r().to_bytes());
    let sig_s_hex = hex::encode(sig.s().to_bytes());

    let shard_files = read_manifest(&manifest_path)?;
    let leaf_index = find_address_index(&shard_files, &address)
        .with_context(|| format!("address {address} not found in shards"))?;

    let env = Environment::new()
        .set_max_dbs(MAX_DBS)
        .open(&db_path)
        .with_context(|| format!("failed to open lmdb env at {}", db_path.display()))?;
    let nodes_db = env
        .open_db(Some("nodes"))
        .context("failed to open nodes db")?;
    let meta_db = env
        .open_db(Some("meta"))
        .context("failed to open meta db")?;

    let (leaf_hash, root_val, merkle_path, merkle_pos) =
        build_membership(&env, nodes_db, meta_db, leaf_index)?;
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let computed_leaf = hash_address(&address, &mut poseidon, Fr::zero())?;
    if computed_leaf != leaf_hash {
        bail!("stored leaf does not match Poseidon(address)");
    }
    // Nullifier = Poseidon(Poseidon(sig_r, sig_s), DROP_DOMAIN)
    let sig_r_fr = fr_from_hex32(&sig_r_hex)?;
    let sig_s_fr = fr_from_hex32(&sig_s_hex)?;
    let identity = poseidon_hash2(sig_r_fr, sig_s_fr)?;
    let drop_domain = Fr::from(DROP_DOMAIN);
    let nullifier = poseidon_hash2(identity, drop_domain)?;

    let proof = ProofSim {
        message: args.message,
        message_sha256: hex::encode(msg_digest),
        address: address.clone(),
        recipient,
        pubkey: PubKey {
            x: pk_x_hex,
            y: pk_y_hex,
        },
        signature: Sig {
            r: sig_r_hex,
            s: sig_s_hex,
        },
        leaf_index: leaf_index as u64,
        leaf_hash: leaf_hash.into_bigint().to_string(),
        nullifier: nullifier.into_bigint().to_string(),
        root: root_val.into_bigint().to_string(),
        merkle_path: merkle_path
            .into_iter()
            .map(|h| h.into_bigint().to_string())
            .collect(),
        merkle_pos,
    };

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&proof)?;
    fs::write(&output_path, json)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    println!("Wrote {}", output_path.display());
    Ok(())
}

fn build_membership(
    env: &Environment,
    nodes_db: Database,
    meta_db: Database,
    leaf_index: usize,
) -> Result<(Fr, Fr, Vec<Fr>, Vec<u8>)> {
    let read_tx = env.begin_ro_txn()?;
    let (depth_meta, leaf_count) = {
        let bytes = read_tx.get(meta_db, b"depth")?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        let depth_meta = u32::from_be_bytes(arr) as usize;
        let lc_bytes = read_tx.get(meta_db, b"leaf_count")?;
        let mut lc_arr = [0u8; 8];
        lc_arr.copy_from_slice(lc_bytes);
        let lc = u64::from_be_bytes(lc_arr);
        (depth_meta, lc as usize)
    };
    // Use leaf_count to derive actual depth (power-of-two trees store root at log2(leaf_count) levels).
    let depth = compute_tree_depth(leaf_count, depth_meta);

    let root_val = {
        let bytes = read_tx.get(meta_db, b"root")?;
        bytes_to_fr(bytes)?
    };

    let leaf = get_node(&read_tx, nodes_db, 0, leaf_index as u64)
        .with_context(|| format!("missing leaf at idx {leaf_index}"))?;

    let mut path = Vec::with_capacity(depth);
    let mut pos = Vec::with_capacity(depth);
    let mut idx = leaf_index as u64;
    for level in 0..depth {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        let sibling = get_node(&read_tx, nodes_db, level as u32, sibling_idx)
            .with_context(|| format!("missing sibling at level {level}, idx {sibling_idx}"))?;
        path.push(sibling);
        pos.push(if idx.is_multiple_of(2) { 0 } else { 1 });
        idx /= 2;
    }

    Ok((leaf, root_val, path, pos))
}
