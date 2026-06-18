use anyhow::Result;
use clap::Parser;

use wallet_sdk_core::keys::Mnemonic;

use crate::config::Keystore;

#[derive(Parser, Debug)]
pub struct Args {
    /// Account name.
    pub name: String,
    /// BIP-39 mnemonic phrase. UNSAFE: appears in the process listing and shell
    /// history. Omit it to enter the phrase via a non-echoing interactive prompt
    /// instead (the canonical path), or set OROGEN_MNEMONIC for scripted use.
    #[arg(long)]
    pub mnemonic: Option<String>,
    #[arg(long)]
    pub passphrase: Option<String>,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let phrase = super::resolve_mnemonic(args.mnemonic.as_deref())?;
    let m = Mnemonic::from_phrase(&phrase)?;
    let file = ks.save_new(&args.name, &m, &pw)?;
    println!("Imported account '{}'", file.name);
    println!("  ss58: {}", file.ss58);
    println!("  eth:  {}", file.eth);
    Ok(())
}
