use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use wallet_sdk_core::keys::Sr25519Keypair;
use wallet_sdk_core::signing::{sign_blake2_domain, DOMAIN_STAKE};

use crate::config::Keystore;

#[derive(Parser, Debug)]
pub struct Args {
    pub name: String,
    #[arg(long)]
    pub amount: u128,
    #[arg(long)]
    pub passphrase: Option<String>,
}

#[derive(Debug, Serialize)]
struct Payload {
    call: &'static str,
    amount: u128,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let m = ks.unlock(&args.name, &pw)?;
    let kp = Sr25519Keypair::from_mnemonic(&m)?;
    let payload = Payload {
        call: "stake",
        amount: args.amount,
    };
    let body = serde_json::to_vec(&payload)?;
    // Domain-prefixed signature (security audit M-W-04).
    let sig = sign_blake2_domain(&kp, DOMAIN_STAKE, &body);
    println!(
        "{{\"payload\":{},\"signature\":\"0x{}\"}}",
        serde_json::to_string(&payload)?,
        hex::encode(sig)
    );
    Ok(())
}
