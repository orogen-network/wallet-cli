use anyhow::Result;
use clap::Parser;

use wallet_sdk_core::keys::Mnemonic;

use crate::config::Keystore;

#[derive(Parser, Debug)]
pub struct Args {
    /// Account name (must be unique within keystore).
    pub name: String,
    /// Encryption passphrase (also reads $OROGEN_PASSPHRASE).
    #[arg(long)]
    pub passphrase: Option<String>,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let mnemonic = Mnemonic::generate()?;
    let file = ks.save_new(&args.name, &mnemonic, &pw)?;
    println!("Created account '{}'", file.name);
    println!("  ss58: {}", file.ss58);
    println!("  eth:  {}", file.eth);
    println!("Mnemonic (write it down NOW, it will not be shown again):");
    println!("  {}", mnemonic.phrase());
    Ok(())
}
