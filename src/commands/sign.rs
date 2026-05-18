use anyhow::Result;
use clap::Parser;

use wallet_sdk_core::keys::Sr25519Keypair;
use wallet_sdk_core::signing::{sign_blake2_domain, DOMAIN_ADHOC};

use crate::config::Keystore;

#[derive(Parser, Debug)]
pub struct Args {
    /// Account name.
    pub name: String,
    /// Payload as hex (with or without 0x prefix).
    pub payload_hex: String,
    #[arg(long)]
    pub passphrase: Option<String>,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let m = ks.unlock(&args.name, &pw)?;
    let kp = Sr25519Keypair::from_mnemonic(&m)?;
    let payload_str = args.payload_hex.strip_prefix("0x").unwrap_or(&args.payload_hex);
    let payload = hex::decode(payload_str)?;
    // Tag the signature so it cannot collide with a structured-message
    // signature (heartbeat / register_operator / stake) — security audit
    // M-W-04. The `--raw` extrinsic submit path (commands/submit.rs) is
    // separate and routes through subxt's own SignedPayload tagging.
    let sig = sign_blake2_domain(&kp, DOMAIN_ADHOC, &payload);
    println!("0x{}", hex::encode(sig));
    Ok(())
}
