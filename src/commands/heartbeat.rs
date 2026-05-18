//! `heartbeat-test` — emit a signed RFC-0003-shaped heartbeat payload.
//!
//! Used by ops to verify a hotkey is correctly registered before pointing the
//! actual worker daemon at it.

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use wallet_sdk_core::keys::Sr25519Keypair;
use wallet_sdk_core::signing::{sign_blake2_domain, DOMAIN_HEARTBEAT};

use crate::config::Keystore;

#[derive(Parser, Debug)]
pub struct Args {
    pub name: String,
    #[arg(long, default_value = "")]
    pub gpu_model: String,
    #[arg(long, default_value = "0")]
    pub free_kv_blocks: u32,
    #[arg(long)]
    pub passphrase: Option<String>,
}

/// RFC-0003 placeholder: a real heartbeat carries an attestation reference,
/// current-job count, etc. Skeleton only.
#[derive(Debug, Serialize)]
struct Heartbeat {
    version: u8,
    operator_ss58: String,
    timestamp_ms: u64,
    gpu_model: String,
    free_kv_blocks: u32,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let m = ks.unlock(&args.name, &pw)?;
    let kp = Sr25519Keypair::from_mnemonic(&m)?;

    let account = ks.load(&args.name)?;
    let hb = Heartbeat {
        version: 1,
        operator_ss58: account.ss58,
        timestamp_ms: now_ms(),
        gpu_model: args.gpu_model,
        free_kv_blocks: args.free_kv_blocks,
    };
    let body = serde_json::to_vec(&hb)?;
    // Domain-prefixed signature (security audit M-W-04): the heartbeat tag
    // makes the resulting signature unusable as a register_operator / stake /
    // ad-hoc-message signature even if an attacker can shape the JSON.
    let sig = sign_blake2_domain(&kp, DOMAIN_HEARTBEAT, &body);
    println!(
        "{{\"heartbeat\":{},\"signature\":\"0x{}\"}}",
        serde_json::to_string(&hb)?,
        hex::encode(sig)
    );
    Ok(())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
