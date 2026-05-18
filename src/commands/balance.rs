//! `balance` — query `System::Account` storage and print free balance.
//!
//! Dynamic storage lookup keeps us decoupled from runtime version. If the
//! chain-node is down we error out (read failure cannot meaningfully fall
//! back to a cached stub on a balance query — operators would risk acting
//! on stale data).

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use subxt::dynamic::{self, Value};
use subxt::ext::scale_value::{Composite, ValueDef};
use subxt::utils::AccountId32;

use crate::config::Keystore;
use crate::rpc::{connect_blocking, DEFAULT_RPC_URL};
use wallet_sdk_core::addresses::ss58_to_account_id;

#[derive(Parser, Debug)]
pub struct Args {
    /// Account name in the local keystore, or a literal SS58 address.
    pub account: String,

    /// WebSocket RPC URL of the chain-node.
    #[arg(long, env = "OROGEN_RPC_URL", default_value = DEFAULT_RPC_URL)]
    pub rpc_url: String,
}

pub fn run(args: Args, ks: &Keystore) -> Result<()> {
    let ss58 = resolve_ss58(&args.account, ks)?;
    let account_bytes = ss58_to_account_id(&ss58)
        .map_err(|e| anyhow!("invalid ss58 address {ss58}: {e}"))?;
    let account_id = AccountId32::from(account_bytes);

    let (rt, client) = connect_blocking(&args.rpc_url)?;

    // System.Account(account_id) -> AccountInfo<Index, AccountData>
    let key = dynamic::storage("System", "Account", vec![Value::from_bytes(account_id.0)]);
    let raw = rt.block_on(async {
        client
            .storage()
            .at_latest()
            .await
            .context("fetch latest block hash")?
            .fetch(&key)
            .await
            .context("storage fetch System.Account")
    })?;

    let raw = raw.ok_or_else(|| anyhow!("account {ss58} not found on chain"))?;
    let decoded = raw.to_value().context("decode AccountInfo Value")?;
    // AccountInfo is a struct {nonce, consumers, providers, sufficients, data: AccountData}
    // AccountData is {free, reserved, frozen, flags} for substrate >=0.9.43.
    let data = field(&decoded, "data")
        .ok_or_else(|| anyhow!("AccountInfo missing `data` field"))?;
    let free = field(data, "free")
        .ok_or_else(|| anyhow!("AccountData missing `free` field"))?;
    let free_str = format!("{free:?}");

    println!("ss58: {ss58}");
    println!("free: {free_str}");
    Ok(())
}

/// Look up `name` in a `Value::Composite::Named(_)`. Returns `None` for
/// any other shape.
fn field<'a, T>(value: &'a Value<T>, name: &str) -> Option<&'a Value<T>> {
    match &value.value {
        ValueDef::Composite(Composite::Named(fields)) => {
            fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
        }
        _ => None,
    }
}

fn resolve_ss58(account: &str, ks: &Keystore) -> Result<String> {
    // Heuristic: SS58 addresses start with a base58 alphabet char and are
    // 47-49 chars long. Keystore names are arbitrary; we try lookup first,
    // then fall through to treating the argument as a literal address.
    if let Ok(file) = ks.load(account) {
        return Ok(file.ss58);
    }
    Ok(account.to_string())
}
