//! `heartbeat-test` — emit a signed RFC-0003 heartbeat payload, or (with
//! `--submit`) submit the on-chain `OperatorStake::heartbeat` extrinsic.
//!
//! Two modes:
//!   * default — print a domain-signed heartbeat JSON for the gateway
//!     `/internal/heartbeat` ingest (verify a hotkey before pointing the
//!     worker daemon at it).
//!   * `--submit --epoch N` — submit the on-chain liveness heartbeat
//!     `OperatorStake::heartbeat(epoch_number, capabilities_summary_hash,
//!     attestation_report_hash)`. The runtime requires
//!     `epoch_number >= last_heartbeat_epoch` and advance <=
//!     `MaxHeartbeatEpochAdvance` (1 on Forge), so supply the current epoch.
//!
//! The production heartbeat loop lives in `worker-control-plane`; this command
//! is for operator-side verification and manual submission.

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use subxt::dynamic::Value;
use subxt::tx::dynamic as dynamic_tx;
use subxt_signer::bip39::Mnemonic as SubxtMnemonic;
use subxt_signer::sr25519::Keypair as SubxtKeypair;

use wallet_sdk_core::keys::{Mnemonic, Sr25519Keypair};
use wallet_sdk_core::signing::{sign_blake2_domain, DOMAIN_HEARTBEAT};

use crate::commands::register_operator::parse_h256;
use crate::config::Keystore;
use crate::rpc::{connect_blocking, DEFAULT_RPC_URL};

#[derive(Parser, Debug)]
pub struct Args {
    pub name: String,
    #[arg(long, default_value = "")]
    pub gpu_model: String,
    #[arg(long, default_value = "0")]
    pub free_kv_blocks: u32,
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Submit the on-chain `OperatorStake::heartbeat` extrinsic instead of
    /// printing a signed gateway payload.
    #[arg(long)]
    pub submit: bool,
    /// Epoch number for the on-chain heartbeat (required with `--submit`).
    #[arg(long)]
    pub epoch: Option<u64>,
    /// Capabilities summary hash (`H256` hex). Defaults to the zero hash.
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub capabilities_hash: String,
    /// Attestation report hash (`H256` hex). Defaults to the zero hash.
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub attestation_hash: String,
    #[arg(long, env = "OROGEN_RPC_URL", default_value = DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

/// RFC-0003 gateway heartbeat payload (off-chain routing liveness).
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

    if args.submit {
        return submit_onchain(&args, &m);
    }

    let kp = Sr25519Keypair::from_mnemonic(&m)?;
    let account = ks.load(&args.name)?;
    let hb = Heartbeat {
        version: 1,
        operator_ss58: account.ss58,
        timestamp_ms: now_ms(),
        gpu_model: args.gpu_model.clone(),
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

fn submit_onchain(args: &Args, mnemonic: &Mnemonic) -> Result<()> {
    let epoch = args
        .epoch
        .context("--epoch is required with --submit (supply the current chain epoch)")?;
    let capabilities = parse_h256(&args.capabilities_hash)
        .with_context(|| format!("invalid --capabilities-hash {}", args.capabilities_hash))?;
    let attestation = parse_h256(&args.attestation_hash)
        .with_context(|| format!("invalid --attestation-hash {}", args.attestation_hash))?;

    let phrase = mnemonic.phrase();
    let bip39 = SubxtMnemonic::parse(phrase.as_str()).context("re-parse mnemonic")?;
    let signer =
        SubxtKeypair::from_phrase(&bip39, None).context("derive subxt-signer keypair")?;

    let (rt, client) = connect_blocking(&args.rpc_url)?;

    let call = dynamic_tx(
        "OperatorStake",
        "heartbeat",
        vec![
            ("epoch_number", Value::u128(epoch as u128)),
            ("capabilities_summary_hash", Value::from_bytes(capabilities)),
            ("attestation_report_hash", Value::from_bytes(attestation)),
        ],
    );

    let hash = rt.block_on(async {
        client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await
            .context("sign_and_submit_default OperatorStake::heartbeat")
    })?;

    println!(
        "submitted heartbeat operator={} epoch={} tx_hash=0x{}",
        args.name,
        epoch,
        hex::encode(hash.as_ref())
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
