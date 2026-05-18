use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use wallet_sdk_core::keys::Sr25519Keypair;
use wallet_sdk_core::signing::{sign_blake2_domain, DOMAIN_REGISTER_OPERATOR};

use crate::config::Keystore;

/// Sign a `register_operator` call payload. Does NOT submit on-chain — that
/// awaits a real RPC endpoint and is gated behind a follow-up RFC.
#[derive(Parser, Debug)]
pub struct Args {
    pub name: String,
    /// Stake amount (atomic units).
    #[arg(long)]
    pub stake: u128,
    /// Comma-separated list of GPU class strings, e.g. "H100,A100".
    #[arg(long)]
    pub gpu_classes: String,
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, Serialize)]
struct Payload {
    call: &'static str,
    stake: u128,
    gpu_classes: Vec<String>,
    nonce: u64,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let m = ks.unlock(&args.name, &pw)?;
    let kp = Sr25519Keypair::from_mnemonic(&m)?;

    let payload = Payload {
        call: "register_operator",
        stake: args.stake,
        gpu_classes: args
            .gpu_classes
            .split(',')
            .map(|s| s.trim().to_string())
            .collect(),
        nonce: now_nonce(),
    };
    let body = serde_json::to_vec(&payload)?;
    // Domain-prefixed signature (security audit M-W-04).
    let sig = sign_blake2_domain(&kp, DOMAIN_REGISTER_OPERATOR, &body);
    println!(
        "{{\"payload\":{},\"signature\":\"0x{}\"}}",
        serde_json::to_string(&payload)?,
        hex::encode(sig)
    );
    Ok(())
}

fn now_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
