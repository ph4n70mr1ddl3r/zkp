use anyhow::Result;
use clap::Parser;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::Signature;
use sha2::{Digest, Sha256};

use zk_airdrop::parse_privkey;

/// Deterministic (RFC6979) ECDSA signature over SHA-256(message).
#[derive(Debug, Parser)]
#[command(name = "deterministic-sign")]
#[command(about = "Sign a message deterministically with secp256k1 ECDSA")]
struct Args {
    /// 32-byte hex private key (0x-prefixed or not).
    privkey: String,
    /// Message to sign (UTF-8); hashed with SHA-256 before signing.
    message: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let sk = parse_privkey(&args.privkey)?;

    let mut hasher = Sha256::new();
    hasher.update(args.message.as_bytes());
    let digest = hasher.finalize();

    let sig: Signature = sk.sign_prehash(&digest).map_err(|e| anyhow::anyhow!(e))?;

    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();
    let mut rs_bytes = Vec::with_capacity(64);
    rs_bytes.extend_from_slice(&r_bytes);
    rs_bytes.extend_from_slice(&s_bytes);
    let rs_hex = hex::encode(rs_bytes);

    println!("message_sha256: {}", hex::encode(digest));
    println!("r: {}", hex::encode(r_bytes));
    println!("s: {}", hex::encode(s_bytes));
    println!("signature_hex: {}", rs_hex);
    Ok(())
}
