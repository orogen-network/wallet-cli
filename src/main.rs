//! `wallet-cli` — command-line wallet for Orogen operators and validators.
//!
//! Layout:
//! - `commands` — one module per top-level CLI subcommand.
//! - `config`   — keystore + on-disk layout.
//!
//! All subcommands operate against `~/.config/llm-mining/keys/`, encrypted at
//! rest with Argon2id-derived ChaCha20-Poly1305 keys. The same on-disk format
//! will be consumed by the operator-daemon (worker-control-plane) when it
//! needs to sign heartbeats with the same hotkey.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
mod config;
mod rpc;

#[derive(Parser, Debug)]
#[command(
    name = "wallet-cli",
    version,
    about = "Orogen wallet CLI",
    long_about = "Manage hotkeys, coldkeys, and operator/validator on-chain registrations \
                  for the Orogen network."
)]
struct Cli {
    /// Override keystore directory (default `~/.config/llm-mining/keys`).
    #[arg(long, env = "OROGEN_KEYSTORE")]
    keystore: Option<std::path::PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Create a new account (sr25519 + EVM-bridge keys derived from one mnemonic).
    New(commands::new::Args),
    /// Import an existing account from a BIP-39 mnemonic.
    Import(commands::import::Args),
    /// List accounts in the keystore.
    List,
    /// Show addresses for a named account.
    Address(commands::address::Args),
    /// Sign an arbitrary payload (hex) with a named account's hotkey.
    Sign(commands::sign::Args),
    /// Submit an extrinsic. Wraps payload in `system.remark` by default; pass
    /// `--raw` to forward a pre-encoded SCALE blob via `author_submitExtrinsic`.
    SubmitExtrinsic(commands::submit::Args),
    /// Query the free balance of an account from `System::Account`.
    Balance(commands::balance::Args),
    /// Submit a `pallet_balances::transfer_keep_alive` extrinsic.
    Transfer(commands::transfer::Args),
    /// Register as an operator (signature only — chain submission stubbed).
    RegisterOperator(commands::register_operator::Args),
    /// Stake tokens (signature only).
    Stake(commands::stake::Args),
    /// Emit a test heartbeat payload (RFC-0003 shape, signed locally).
    HeartbeatTest(commands::heartbeat::Args),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let keystore = config::Keystore::open(cli.keystore.clone())?;

    match cli.cmd {
        Cmd::New(a) => commands::new::run(a, &keystore),
        Cmd::Import(a) => commands::import::run(a, &keystore),
        Cmd::List => commands::list::run(&keystore),
        Cmd::Address(a) => commands::address::run(a, &keystore),
        Cmd::Sign(a) => commands::sign::run(a, &keystore),
        Cmd::SubmitExtrinsic(a) => commands::submit::run(a, &keystore),
        Cmd::Balance(a) => commands::balance::run(a, &keystore),
        Cmd::Transfer(a) => commands::transfer::run(a, &keystore),
        Cmd::RegisterOperator(a) => commands::register_operator::run(a, &keystore),
        Cmd::Stake(a) => commands::stake::run(a, &keystore),
        Cmd::HeartbeatTest(a) => commands::heartbeat::run(a, &keystore),
    }
}
