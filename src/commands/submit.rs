//! `submit-extrinsic` — submit a `system::remark` carrying the user's payload.
//!
//! Two input modes:
//!   1. `payload-hex` (a freeform byte string we wrap in `system.remark`).
//!   2. `--raw` (a pre-encoded SCALE extrinsic blob the user wants forwarded
//!      verbatim — useful for advanced flows + chaos tests).
//!
//! Both paths go through the real subxt RPC client. If the chain-node is not
//! reachable, we surface a friendly error pointing at `--dev`.

use std::io::{self, BufRead, Write};

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
    /// Hex-encoded payload (will be wrapped in `system.remark`). The `0x`
    /// prefix is optional.
    pub payload_hex: String,

    /// Keystore account whose hotkey signs the extrinsic.
    #[arg(long, default_value = "default")]
    pub from: String,

    /// Keystore passphrase. Falls back to `OROGEN_PASSPHRASE` env var.
    #[arg(long)]
    pub passphrase: Option<String>,

    /// WebSocket RPC URL of the chain-node.
    #[arg(long, env = "OROGEN_RPC_URL", default_value = DEFAULT_RPC_URL)]
    pub rpc_url: String,

    /// Treat `payload_hex` as a pre-encoded extrinsic blob and submit it
    /// verbatim via `author_submitExtrinsic`.
    #[arg(long)]
    pub raw: bool,

    /// Skip the interactive confirmation prompt printed before a `--raw`
    /// extrinsic submission. Intended for non-interactive scripts and CI;
    /// human users should leave this off so the security-audit M-W-01
    /// confirmation is shown.
    #[arg(long, env = "OROGEN_RAW_YES")]
    pub yes: bool,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let payload = decode_hex(&args.payload_hex)?;

    if args.raw {
        // M-W-01: a `--raw` extrinsic is opaque bytes that will be submitted
        // verbatim. Show the user how many bytes they're about to forward and
        // a short hex preview, and require an explicit `YES` confirmation
        // unless `--yes` (or the `OROGEN_RAW_YES` env var) is set. Decoding
        // pallet/call/args from SCALE without metadata is not feasible here;
        // the explicit confirmation is the practical safeguard.
        if !args.yes {
            confirm_raw_extrinsic(&payload)?;
        }
        // Raw mode: forward the bytes to author_submitExtrinsic directly via
        // the wallet-sdk-core WS client (no signer/runtime context needed).
        use wallet_sdk_core::rpc::{ClientFactory, RpcClient};
        let client = ClientFactory::ws(&args.rpc_url).map_err(|e| {
            anyhow::anyhow!(
                "chain-node not reachable at {}; start it with \
                 `cargo run --bin chain-node -- --dev` ({})",
                args.rpc_url,
                e
            )
        })?;
        let hash = client
            .submit_extrinsic(&payload)
            .map_err(|e| anyhow::anyhow!("submit_extrinsic: {e}"))?;
        println!("submitted (raw) tx_hash={hash}");
        return Ok(());
    }

    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let mnemonic = ks.unlock(&args.from, &pw)?;

    let signer_phrase = mnemonic.phrase();
    let bip39 = SubxtMnemonic::parse(signer_phrase.as_str()).context("re-parse mnemonic")?;
    let signer =
        SubxtKeypair::from_phrase(&bip39, None).context("derive subxt-signer keypair")?;

    let (rt, client) = connect_blocking(&args.rpc_url)?;

    // Build a dynamic `system.remark { remark: Vec<u8> }` call. Using the
    // dynamic API means we adapt to whatever runtime version the node
    // advertises without recompiling.
    let call = dynamic_tx(
        "System",
        "remark",
        vec![("remark", Value::from_bytes(payload.clone()))],
    );

    let hash = rt.block_on(async {
        client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await
            .context("sign_and_submit_default")
    })?;

    println!("submitted tx_hash=0x{}", hex::encode(hash.as_ref()));
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s).context("payload is not valid hex")?)
}

/// Print a short summary of the opaque blob and require the operator to type
/// `YES` on stdin before we forward it to the chain. Security audit M-W-01.
fn confirm_raw_extrinsic(payload: &[u8]) -> Result<()> {
    let preview_len = core::cmp::min(payload.len(), 32);
    let preview = hex::encode(&payload[..preview_len]);
    let ellipsis = if payload.len() > preview_len { "..." } else { "" };
    eprintln!("--- raw extrinsic confirmation (security audit M-W-01) ---");
    eprintln!("  size      : {} bytes", payload.len());
    eprintln!("  prefix    : 0x{preview}{ellipsis}");
    eprintln!("This blob will be submitted to the chain verbatim. Pallet/call");
    eprintln!("decoding without runtime metadata is not available here.");
    eprintln!("Type YES (uppercase) to confirm, anything else to abort.");
    let _ = io::stderr().flush();
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .context("reading confirmation from stdin")?;
    if answer.trim() != "YES" {
        return Err(anyhow!("aborted by user (raw extrinsic confirmation)"));
    }
    Ok(())
}
