use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail, ensure};
use hex::FromHex;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use num_bigint::BigUint;
use serde::Deserialize;
use tempfile::NamedTempFile;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:?}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = Config::from_env()?;

    let wallet_file = read_wallet_file(&config.pubkeys_path)?;
    let merkle_file = read_merkle_file(&config.merkle_tree_path)?;

    ensure!(
        config.wallet_index < wallet_file.wallets.len(),
        "wallet index {} exceeds stored wallets ({} found)",
        config.wallet_index,
        wallet_file.wallets.len()
    );
    ensure!(
        merkle_file.depth == wallet_file.merkle_depth,
        "merkle depth mismatch (tree={}, config={})",
        merkle_file.depth,
        wallet_file.merkle_depth
    );

    let wallet = &wallet_file.wallets[config.wallet_index];
    let pk_x_limbs = parse_biguint_vec(&wallet.public_key.x_limbs)?;
    let pk_y_limbs = parse_biguint_vec(&wallet.public_key.y_limbs)?;

    let merkle_layers = parse_layers(&merkle_file.layers)?;
    ensure!(
        merkle_layers.len() == merkle_file.depth + 1,
        "expected {} merkle layers, got {}",
        merkle_file.depth + 1,
        merkle_layers.len()
    );
    let merkle_root = merkle_layers
        .last()
        .and_then(|layer| layer.first())
        .cloned()
        .context("missing merkle root")?;
    let (merkle_siblings, merkle_pos) =
        merkle_proof(&merkle_layers, config.wallet_index, merkle_file.depth)?;

    let (sig_r, sig_s) = sign_identity(&wallet.private_key, &wallet_file.identity_message_hash)?;
    let sig_r_limbs = to_limbs(&sig_r, wallet_file.limb_bits, wallet_file.limb_count);
    let sig_s_limbs = to_limbs(&sig_s, wallet_file.limb_bits, wallet_file.limb_count);

    // Hash limbs and derive nullifier/vote hash using circomlib's Poseidon (via Node).
    let r_pack = poseidon_hash(&sig_r_limbs, &config.project_root)?;
    let s_pack = poseidon_hash(&sig_s_limbs, &config.project_root)?;
    let identity_secret = poseidon_hash(&[r_pack.clone(), s_pack.clone()], &config.project_root)?;
    let nullifier = poseidon_hash(
        &[identity_secret.clone(), config.proposal_id.clone()],
        &config.project_root,
    )?;
    let vote_hash = poseidon_hash(&[config.vote_choice.clone()], &config.project_root)?;

    let witness_input = build_witness_input(
        &merkle_root,
        &config,
        &pk_x_limbs,
        &pk_y_limbs,
        &sig_r_limbs,
        &sig_s_limbs,
        &merkle_siblings,
        &merkle_pos,
        &nullifier,
        &vote_hash,
    );

    let input_file = write_temp_json(&witness_input)?;
    let witness_file = NamedTempFile::new()?;
    run_snarkjs_witness(&config, input_file.path(), witness_file.path())?;
    run_snarkjs_prove(&config, witness_file.path())?;

    println!("Proof written to {}", config.proof_path.display());
    println!("Public signals written to {}", config.public_path.display());
    println!("Nullifier: {nullifier}");
    println!("Vote hash: {vote_hash}");

    Ok(())
}

#[derive(Debug)]
struct Config {
    wallet_index: usize,
    proposal_id: BigUint,
    vote_choice: BigUint,
    project_root: PathBuf,
    wasm_path: PathBuf,
    zkey_path: PathBuf,
    proof_path: PathBuf,
    public_path: PathBuf,
    pubkeys_path: PathBuf,
    merkle_tree_path: PathBuf,
}

impl Config {
    fn from_env() -> Result<Self> {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("failed to locate project root")?
            .to_path_buf();

        let wallet_index = env::var("WALLET_INDEX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let proposal_id = env::var("PROPOSAL_ID")
            .ok()
            .map(|v| parse_decimal(&v))
            .transpose()?
            .unwrap_or_else(|| BigUint::from(1u32));
        let vote_choice = env::var("VOTE_CHOICE")
            .ok()
            .map(|v| parse_decimal(&v))
            .transpose()?
            .unwrap_or_else(|| BigUint::from(2u32));

        let wasm_path = env::var("WASM_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| project_root.join("build/zkvote_js/zkvote.wasm"));
        let zkey_path = env::var("ZKEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| project_root.join("build/zkvote_final.zkey"));

        Ok(Self {
            wallet_index,
            proposal_id,
            vote_choice,
            wasm_path,
            zkey_path,
            proof_path: project_root.join("data/proof.json"),
            public_path: project_root.join("data/public.json"),
            pubkeys_path: project_root.join("data/pubkeys.json"),
            merkle_tree_path: project_root.join("data/merkle_tree.json"),
            project_root,
        })
    }
}

#[derive(Debug, Deserialize)]
struct WalletFile {
    #[serde(rename = "limbBits")]
    limb_bits: usize,
    #[serde(rename = "limbCount")]
    limb_count: usize,
    #[serde(rename = "merkleDepth")]
    merkle_depth: usize,
    #[serde(rename = "identityMessageHash")]
    identity_message_hash: String,
    wallets: Vec<StoredWallet>,
}

#[derive(Debug, Deserialize)]
struct StoredWallet {
    #[serde(rename = "privateKey")]
    private_key: String,
    #[serde(rename = "publicKey")]
    public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
struct PublicKey {
    x: String,
    y: String,
    #[serde(rename = "xLimbs")]
    x_limbs: Vec<String>,
    #[serde(rename = "yLimbs")]
    y_limbs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MerkleFile {
    depth: usize,
    layers: Vec<Vec<String>>,
}

fn read_wallet_file(path: &Path) -> Result<WalletFile> {
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed: WalletFile = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(parsed)
}

fn read_merkle_file(path: &Path) -> Result<MerkleFile> {
    let data =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed: MerkleFile = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(parsed)
}

fn parse_decimal(value: &str) -> Result<BigUint> {
    BigUint::parse_bytes(value.as_bytes(), 10).context("invalid decimal value")
}

fn parse_biguint_vec(values: &[String]) -> Result<Vec<BigUint>> {
    values.iter().map(|v| parse_decimal(v)).collect()
}

fn parse_layers(raw: &[Vec<String>]) -> Result<Vec<Vec<BigUint>>> {
    raw.iter().map(|layer| parse_biguint_vec(layer)).collect()
}

fn to_limbs(value: &BigUint, limb_bits: usize, limb_count: usize) -> Vec<BigUint> {
    let mask = (BigUint::from(1u32) << limb_bits) - 1u32;
    let mut out = Vec::with_capacity(limb_count);
    let mut remaining = value.clone();
    for _ in 0..limb_count {
        let limb = &remaining & &mask;
        out.push(limb);
        remaining >>= limb_bits;
    }
    out
}

fn merkle_proof(
    layers: &[Vec<BigUint>],
    index: usize,
    depth: usize,
) -> Result<(Vec<BigUint>, Vec<u8>)> {
    let mut idx = index;
    let mut siblings = Vec::with_capacity(depth);
    let mut positions = Vec::with_capacity(depth);
    for level in 0..depth {
        let layer = layers
            .get(level)
            .with_context(|| format!("missing layer {level} when building merkle proof"))?;
        ensure!(
            idx < layer.len(),
            "leaf index {index} out of bounds for layer {level}"
        );
        let is_right = idx % 2;
        let pair_index = if is_right == 1 { idx - 1 } else { idx + 1 };
        let sibling = layer
            .get(pair_index)
            .cloned()
            .context("missing sibling when building merkle proof")?;
        siblings.push(sibling);
        positions.push(is_right as u8);
        idx /= 2;
    }
    Ok((siblings, positions))
}

fn sign_identity(private_key_hex: &str, digest_hex: &str) -> Result<(BigUint, BigUint)> {
    let priv_bytes = Vec::from_hex(private_key_hex.trim_start_matches("0x"))
        .context("invalid private key hex")?;
    let digest_vec = Vec::from_hex(digest_hex.trim_start_matches("0x"))
        .context("invalid identity digest hex")?;
    let digest_bytes: [u8; 32] = digest_vec
        .try_into()
        .map_err(|_| anyhow!("identity hash must be 32 bytes"))?;

    let signing_key = SigningKey::from_slice(&priv_bytes).context("failed to build signing key")?;
    let signature: Signature = signing_key
        .sign_prehash(&digest_bytes)
        .context("failed to sign identity digest")?;

    let r = BigUint::from_bytes_be(signature.r().to_bytes().as_slice());
    let s = BigUint::from_bytes_be(signature.s().to_bytes().as_slice());
    Ok((r, s))
}

fn poseidon_hash(inputs: &[BigUint], project_root: &Path) -> Result<BigUint> {
    let script = r#"
import { buildPoseidon } from 'circomlibjs';

let data = '';
for await (const chunk of process.stdin) {
  data += chunk;
}
const values = JSON.parse(data);
const poseidon = await buildPoseidon();
const F = poseidon.F;
const result = F.toString(poseidon(values.map(BigInt)));
process.stdout.write(result);
"#;

    let mut child = Command::new("node");
    child
        .current_dir(project_root)
        .arg("--input-type=module")
        .arg("-e")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut handle = child.spawn().context("failed to spawn node for poseidon")?;
    if let Some(stdin) = handle.stdin.as_mut() {
        let payload: Vec<String> = inputs.iter().map(|v| v.to_string()).collect();
        let encoded = serde_json::to_vec(&payload)?;
        stdin.write_all(&encoded)?;
    }

    let output = handle
        .wait_with_output()
        .context("failed to run poseidon helper")?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        bail!("poseidon helper failed: {err}");
    }
    let stdout = String::from_utf8(output.stdout)?;
    parse_decimal(stdout.trim())
}

fn build_witness_input(
    merkle_root: &BigUint,
    config: &Config,
    pk_x_limbs: &[BigUint],
    pk_y_limbs: &[BigUint],
    sig_r_limbs: &[BigUint],
    sig_s_limbs: &[BigUint],
    merkle_siblings: &[BigUint],
    merkle_pos: &[u8],
    nullifier: &BigUint,
    vote_hash: &BigUint,
) -> serde_json::Value {
    serde_json::json!({
        "root_pubkeys": merkle_root.to_string(),
        "proposalId": config.proposal_id.to_string(),
        "nullifier": nullifier.to_string(),
        "voteHash": vote_hash.to_string(),
        "vote_choice": config.vote_choice.to_string(),
        "pk_x_limbs": pk_x_limbs.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        "pk_y_limbs": pk_y_limbs.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        "sig_r_limbs": sig_r_limbs.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        "sig_s_limbs": sig_s_limbs.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        "merkle_siblings": merkle_siblings.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
        "merkle_pos": merkle_pos,
    })
}

fn write_temp_json(value: &serde_json::Value) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    let buf = serde_json::to_vec_pretty(value)?;
    file.write_all(&buf)?;
    Ok(file)
}

fn run_snarkjs_witness(config: &Config, input: &Path, witness_out: &Path) -> Result<()> {
    let status = Command::new("node")
        .current_dir(&config.project_root)
        .arg("node_modules/snarkjs/build/cli.cjs")
        .arg("wtns")
        .arg("calculate")
        .arg(&config.wasm_path)
        .arg(input)
        .arg(witness_out)
        .status()
        .context("failed to run snarkjs witness generation")?;
    ensure!(status.success(), "snarkjs witness generation failed");
    Ok(())
}

fn run_snarkjs_prove(config: &Config, witness: &Path) -> Result<()> {
    if let Some(parent) = config.proof_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = config.public_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let status = Command::new("node")
        .current_dir(&config.project_root)
        .arg("node_modules/snarkjs/build/cli.cjs")
        .arg("groth16")
        .arg("prove")
        .arg(&config.zkey_path)
        .arg(witness)
        .arg(&config.proof_path)
        .arg(&config.public_path)
        .status()
        .context("failed to run snarkjs groth16 prove")?;
    ensure!(status.success(), "snarkjs proof generation failed");
    Ok(())
}
