use anyhow::Result;
use clap::Parser;

use crate::config::Keystore;

#[derive(Parser, Debug)]
pub struct Args {
    /// Account name.
    pub name: String,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let f = ks.load(&args.name)?;
    println!("ss58: {}", f.ss58);
    println!("eth:  {}", f.eth);
    Ok(())
}
