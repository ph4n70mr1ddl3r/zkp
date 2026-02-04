use std::fs::File;
use std::io::Read;
use std::str::FromStr;

use anyhow::{anyhow, ensure, Context, Result};
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use clap::Parser;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::EncodedPoint;
use light_poseidon::{Poseidon, PoseidonHasher};
use lmdb::{Environment, Transaction};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use zkvote_proof::{
    compute_tree_depth, eth_address, fr_from_hex32, get_node, hash_address, hash_pair,
    poseidon_hash2, project_root, MAX_DBS,
};

/// Simulated verifier for the private airdrop: checks signature, address binding, Merkle path, and nullifier.
#[derive(Debug, Parser)]
#[command(name = "airdrop-verify-sim")]
#[command(about = "Verify a non-zk airdrop proof artifact")]
struct Args {
    /// Path to the JSON produced by airdrop-prove-sim.
    #[arg(long, default_value = "data/airdrop_proof_sim.json")]
    input: String,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
struct PubKey {
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct Sig {
    r: String,
    s: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut file =
        File::open(&args.input).with_context(|| format!("failed to open {}", args.input))?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let proof: ProofSim =
        serde_json::from_str(&data).with_context(|| format!("failed to parse {}", args.input))?;

    // Rebuild verifying key.
    let vk = pubkey_from_hex(&proof.pubkey.x, &proof.pubkey.y)?;

    // Check address derives from pubkey.
    let derived_addr = eth_address(&vk)?;
    ensure!(
        derived_addr.eq_ignore_ascii_case(&proof.address),
        "address mismatch: derived {derived_addr}, proof {}",
        proof.address
    );

    // Verify signature over SHA-256(message).
    let mut sha = Sha256::new();
    sha.update(proof.message.as_bytes());
    let msg_digest = sha.finalize();
    ensure!(
        hex::encode(msg_digest) == proof.message_sha256,
        "message digest mismatch"
    );
    let sig = signature_from_hex(&proof.signature.r, &proof.signature.s)?;
    vk.verify_prehash(&msg_digest, &sig)
        .map_err(|e| anyhow!("signature verification failed: {e}"))?;

    // Recompute leaf/hash/nullifier.
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let leaf = hash_address(&proof.address, &mut poseidon, Fr::zero())?;
    ensure!(
        leaf.into_bigint().to_string() == proof.leaf_hash,
        "leaf hash mismatch"
    );

    let sig_r_fr = fr_from_hex32(&proof.signature.r)?;
    let sig_s_fr = fr_from_hex32(&proof.signature.s)?;
    let identity = poseidon_hash2(sig_r_fr, sig_s_fr)?;
    let drop_domain = Fr::from(1u64);
    let nullifier = poseidon_hash2(identity, drop_domain)?;
    ensure!(
        nullifier.into_bigint().to_string() == proof.nullifier,
        "nullifier mismatch"
    );

    // Verify Merkle path to root.
    let root = fr_from_dec(&proof.root)?;
    let path: Vec<Fr> = proof
        .merkle_path
        .iter()
        .map(|s| fr_from_dec(s))
        .collect::<Result<_>>()?;
    ensure!(path.len() == proof.merkle_pos.len(), "path length mismatch");
    let computed_root = recompute_root(&leaf, &path, &proof.merkle_pos)?;
    let db_root = recompute_from_db(proof.leaf_index as u64).ok();
    println!("computed root: {}", computed_root.into_bigint());
    if let Some(db) = &db_root {
        println!(
            "merkle.db recompute for idx {} -> {}",
            proof.leaf_index,
            db.into_bigint()
        );
    }
    if computed_root != root {
        anyhow::bail!(
            "computed root does not match provided root (computed={}, provided={}, db={})",
            computed_root.into_bigint(),
            root.into_bigint(),
            db_root.map(|r| r.into_bigint()).unwrap_or_default()
        );
    }

    println!("Verification succeeded.");
    println!("root: {}", proof.root);
    println!("nullifier: {}", proof.nullifier);
    println!("recipient: {}", proof.recipient);
    Ok(())
}

fn pubkey_from_hex(x_hex: &str, y_hex: &str) -> Result<VerifyingKey> {
    let x_bytes = hex::decode(x_hex).context("invalid pubkey x hex")?;
    let y_bytes = hex::decode(y_hex).context("invalid pubkey y hex")?;
    if x_bytes.len() != zkvote_proof::FIELD_ELEMENT_SIZE
        || y_bytes.len() != zkvote_proof::FIELD_ELEMENT_SIZE
    {
        anyhow::bail!(
            "pubkey limbs must be {} bytes each",
            zkvote_proof::FIELD_ELEMENT_SIZE
        );
    }
    let x_arr: [u8; 32] = x_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey x must be 32 bytes"))?;
    let y_arr: [u8; 32] = y_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey y must be 32 bytes"))?;
    let point = EncodedPoint::from_affine_coordinates(&x_arr.into(), &y_arr.into(), false);
    VerifyingKey::from_encoded_point(&point).map_err(|e| anyhow!("invalid pubkey: {e}"))
}

fn signature_from_hex(r_hex: &str, s_hex: &str) -> Result<Signature> {
    let r = hex::decode(r_hex).context("invalid r hex")?;
    let s = hex::decode(s_hex).context("invalid s hex")?;
    if r.len() != zkvote_proof::FIELD_ELEMENT_SIZE || s.len() != zkvote_proof::FIELD_ELEMENT_SIZE {
        anyhow::bail!(
            "signature limbs must be {} bytes each",
            zkvote_proof::FIELD_ELEMENT_SIZE
        );
    }
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&r);
    bytes[32..].copy_from_slice(&s);
    Signature::from_slice(&bytes).map_err(|e| anyhow!("invalid signature: {e}"))
}

fn fr_from_dec(s: &str) -> Result<Fr> {
    Fr::from_str(s).map_err(|_| anyhow!("invalid field element: {s}"))
}

fn recompute_root(leaf: &Fr, path: &[Fr], pos: &[u8]) -> Result<Fr> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let mut current = *leaf;
    for (sib, dir) in path.iter().zip(pos.iter()) {
        current = if *dir == 0 {
            poseidon
                .hash(&[current, *sib])
                .map_err(|e: light_poseidon::PoseidonError| anyhow!(e.to_string()))?
        } else {
            poseidon
                .hash(&[*sib, current])
                .map_err(|e: light_poseidon::PoseidonError| anyhow!(e.to_string()))?
        };
    }
    Ok(current)
}

fn recompute_from_db(idx: u64) -> Result<Fr> {
    let root = project_root()?;
    let db_path = root.join("merkle.db");
    let env = Environment::new().set_max_dbs(MAX_DBS).open(&db_path)?;
    let nodes_db = env.open_db(Some("nodes"))?;
    let meta_db = env.open_db(Some("meta"))?;
    let tx = env.begin_ro_txn()?;
    let depth = {
        let bytes = tx.get(meta_db, b"depth")?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        u32::from_be_bytes(arr) as usize
    };

    // Derive actual depth from leaf_count to avoid off-by-one metadata.
    let leaf_count_bytes = tx.get(meta_db, b"leaf_count")?;
    let mut lc_arr = [0u8; 8];
    lc_arr.copy_from_slice(leaf_count_bytes);
    let leaf_count = u64::from_be_bytes(lc_arr) as usize;
    let depth_actual = compute_tree_depth(leaf_count, depth);

    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let mut current =
        get_node(&tx, nodes_db, 0, idx).with_context(|| format!("missing leaf at idx {idx}"))?;
    let mut cur_idx = idx;
    for level in 0..depth_actual {
        let (left, right) = if cur_idx.is_multiple_of(2) {
            (
                current,
                get_node(&tx, nodes_db, level as u32, cur_idx + 1).with_context(|| {
                    format!("missing sibling at level {level}, idx {}", cur_idx + 1)
                })?,
            )
        } else {
            (
                get_node(&tx, nodes_db, level as u32, cur_idx - 1).with_context(|| {
                    format!("missing sibling at level {level}, idx {}", cur_idx - 1)
                })?,
                current,
            )
        };
        current = hash_pair(&mut poseidon, left, right)?;
        cur_idx /= 2;
    }
    Ok(current)
}
