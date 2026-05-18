use anyhow::Result;

use crate::config::Keystore;

pub fn run(ks: &Keystore) -> Result<()> {
    let accounts = ks.list()?;
    if accounts.is_empty() {
        println!("(no accounts in {})", ks.path().display());
        return Ok(());
    }
    for a in accounts {
        println!("{}\t{}\t{}", a.name, a.ss58, a.eth);
    }
    Ok(())
}
