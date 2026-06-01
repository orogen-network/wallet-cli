//! `register-operator` — submit `OperatorStake::register(stake, attestation_hash)`.
//!
//! RFC-0003: an operator binds a stake-backed hotkey identity on-chain. The
//! extrinsic reserves `stake` (>= runtime `MinStake`) from the caller's free
//! balance for the lifetime of the registration and records the operator's
//! current attestation hash. Reservation is released on `unregister`.
//!
//! `attestation_hash` is an `H256` referencing the operator's attestation
//! report (from `attestation-service`). On the current Forge testnet runtime
//! the value is not yet validated on-chain, so a zero hash is accepted for
//! bring-up; pass `--attestation-hash 0x..` once attestation is wired.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use subxt::dynamic::Value;
use subxt::tx::dynamic as dynamic_tx;
use subxt_signer::bip39::Mnemonic as SubxtMnemonic;
use subxt_signer::sr25519::Keypair as SubxtKeypair;

use crate::config::Keystore;
use crate::rpc::{connect_blocking, DEFAULT_RPC_URL};

#[derive(Parser, Debug)]
pub struct Args {
    /// Operator keystore account name (the stake-backed hotkey).
    pub name: String,

    /// Stake to reserve, in atomic units (plancks). Must be >= runtime
    /// `MinStake` (1_000_000_000_000 = 1 OROG on Forge).
    #[arg(long)]
    pub stake: u128,

    /// Attestation report hash (`H256`), hex with optional `0x` prefix.
    /// Defaults to the zero hash for testnet bring-up.
    #[arg(
        long,
        default_value = "0x0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub attestation_hash: String,

    #[arg(long)]
    pub passphrase: Option<String>,

    #[arg(long, env = "OROGEN_RPC_URL", default_value = DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let mnemonic = ks.unlock(&args.name, &pw)?;

    let phrase = mnemonic.phrase();
    let bip39 = SubxtMnemonic::parse(phrase.as_str()).context("re-parse mnemonic")?;
    let signer =
        SubxtKeypair::from_phrase(&bip39, None).context("derive subxt-signer keypair")?;

    let attestation = parse_h256(&args.attestation_hash)
        .with_context(|| format!("invalid --attestation-hash {}", args.attestation_hash))?;

    let (rt, client) = connect_blocking(&args.rpc_url)?;

    let call = dynamic_tx(
        "OperatorStake",
        "register",
        vec![
            ("stake", Value::u128(args.stake)),
            ("attestation_hash", Value::from_bytes(attestation)),
        ],
    );

    let hash = rt.block_on(async {
        client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await
            .context("sign_and_submit_default OperatorStake::register")
    })?;

    println!(
        "submitted register operator={} stake={} attestation_hash={} tx_hash=0x{}",
        args.name,
        args.stake,
        args.attestation_hash,
        hex::encode(hash.as_ref())
    );
    Ok(())
}

/// Parse a 32-byte hex string (with optional `0x` prefix) into raw bytes.
pub(crate) fn parse_h256(s: &str) -> Result<[u8; 32]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(anyhow!(
            "expected 32-byte (64 hex char) H256, got {} hex chars",
            stripped.len()
        ));
    }
    let bytes = hex::decode(stripped).context("hex decode H256")?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
