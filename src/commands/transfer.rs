//! `transfer` — submit a `Balances::transfer_keep_alive` extrinsic.
//!
//! `keep_alive` is preferred over `transfer` so accidental sends that would
//! reap the sender's account fail loudly instead of silently dust-deleting
//! state. Operators who actually want to drain an account should use the
//! sudo / governance path post-launch.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use subxt::dynamic::Value;
use subxt::tx::dynamic as dynamic_tx;
use subxt::utils::AccountId32;
use subxt_signer::bip39::Mnemonic as SubxtMnemonic;
use subxt_signer::sr25519::Keypair as SubxtKeypair;

use crate::config::Keystore;
use crate::rpc::{connect_blocking, DEFAULT_RPC_URL};
use wallet_sdk_core::addresses::ss58_to_account_id;

#[derive(Parser, Debug)]
pub struct Args {
    /// Sender keystore account name.
    pub from: String,
    /// Recipient SS58 address.
    pub to: String,
    /// Amount in atomic units (plancks, etc).
    pub amount: u128,

    #[arg(long)]
    pub passphrase: Option<String>,

    #[arg(long, env = "OROGEN_RPC_URL", default_value = DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let pw = super::resolve_passphrase(args.passphrase.as_deref())?;
    let mnemonic = ks.unlock(&args.from, &pw)?;

    let phrase = mnemonic.phrase();
    let bip39 = SubxtMnemonic::parse(phrase.as_str()).context("re-parse mnemonic")?;
    let signer =
        SubxtKeypair::from_phrase(&bip39, None).context("derive subxt-signer keypair")?;

    let to_bytes = ss58_to_account_id(&args.to)
        .map_err(|e| anyhow!("invalid `to` ss58 {}: {}", args.to, e))?;
    let to = AccountId32::from(to_bytes);

    let (rt, client) = connect_blocking(&args.rpc_url)?;

    // `dest` is a `MultiAddress<AccountId, AccountIndex>`. We submit the
    // `Id(AccountId32)` variant — the most universally accepted.
    let dest = Value::unnamed_variant("Id", vec![Value::from_bytes(to.0)]);
    let call = dynamic_tx(
        "Balances",
        "transfer_keep_alive",
        vec![("dest", dest), ("value", Value::u128(args.amount))],
    );

    let hash = rt.block_on(async {
        client
            .tx()
            .sign_and_submit_default(&call, &signer)
            .await
            .context("sign_and_submit_default")
    })?;

    println!(
        "submitted transfer from={} to={} amount={} tx_hash=0x{}",
        args.from,
        args.to,
        args.amount,
        hex::encode(hash.as_ref())
    );
    Ok(())
}
