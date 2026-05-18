//! Shared subxt-backed RPC plumbing for the wallet CLI.
//!
//! All on-chain subcommands route through this module: it builds the
//! `OnlineClient<PolkadotConfig>` synchronously (on a private tokio runtime)
//! so callers stay regular blocking Rust functions.
//!
//! When the chain-node is not reachable we surface a clear human-readable
//! error pointing the operator to `cargo run --bin chain-node -- --dev`
//! rather than letting subxt's transport error bubble up raw.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use subxt::{OnlineClient, PolkadotConfig};
use tokio::runtime::Runtime;

/// Default RPC URL used when `--rpc-url` is omitted.
pub const DEFAULT_RPC_URL: &str = "ws://127.0.0.1:9944";

/// Reject non-loopback `ws://` URLs. Security audit H-W-05: plain WebSocket
/// to a remote chain-node would expose the signed extrinsic + bearer-style
/// inputs to a network attacker. Only `wss://` is acceptable for non-loopback
/// hosts.
///
/// Returns the URL unchanged on success (so callers can chain).
fn enforce_ws_scheme(url: &str) -> Result<&str> {
    // We use a lightweight prefix check (rather than a full URL parser) to
    // avoid pulling another dep into wallet-cli. Scheme + authority extraction
    // is sufficient because we already require either `wss://` (always OK) or
    // `ws://<host>[:port][/path]` whose host must be loopback.
    if let Some(rest) = url.strip_prefix("wss://") {
        if rest.is_empty() {
            return Err(anyhow!("rpc url '{url}' is missing the host"));
        }
        return Ok(url);
    }
    if let Some(rest) = url.strip_prefix("ws://") {
        // Extract host. IPv6 literals are wrapped in brackets (`[::1]`).
        let host = if let Some(stripped) = rest.strip_prefix('[') {
            // Match up to the closing `]`.
            let end = stripped
                .find(']')
                .ok_or_else(|| anyhow!("rpc url '{url}' has unbalanced IPv6 brackets"))?;
            &stripped[..end]
        } else {
            let host_end = rest
                .find(|c: char| c == ':' || c == '/')
                .unwrap_or(rest.len());
            &rest[..host_end]
        };
        let host_lc = host.to_ascii_lowercase();
        let is_loopback =
            host_lc == "localhost" || host_lc == "127.0.0.1" || host_lc == "::1";
        if !is_loopback {
            return Err(anyhow!(
                "rpc url '{url}' uses plain ws:// to a non-loopback host '{host}'. \
                 Use wss:// for any remote chain-node; plain ws is only permitted \
                 for 127.0.0.1 / localhost (security audit H-W-05)."
            ));
        }
        return Ok(url);
    }
    Err(anyhow!(
        "rpc url '{url}' must use ws:// (loopback only) or wss:// — \
         http(s):// is not a substrate JSON-RPC transport"
    ))
}

/// Build a small private runtime + reachable subxt client. Returns a friendly
/// error if the chain-node is not running.
///
/// We bound connect attempts at ~3s so misconfigured CIs don't hang.
pub fn connect_blocking(url: &str) -> Result<(Runtime, OnlineClient<PolkadotConfig>)> {
    enforce_ws_scheme(url)?;
    let rt = Runtime::new().context("building tokio runtime")?;
    let url_owned = url.to_string();
    let client_res = rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(3),
            // Use the validating constructor — `from_insecure_url` is only
            // appropriate for self-signed local dev nodes and we have already
            // gated ws:// to loopback above, so https/wss validation applies
            // wherever it matters.
            OnlineClient::<PolkadotConfig>::from_url(&url_owned),
        )
        .await
    });
    let client = match client_res {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            return Err(anyhow!(
                "chain-node not reachable at {url}; start it with \
                 `cargo run --bin chain-node -- --dev` (subxt error: {e})"
            ));
        }
        Err(_) => {
            return Err(anyhow!(
                "chain-node not reachable at {url} (connect timed out); \
                 start it with `cargo run --bin chain-node -- --dev`"
            ));
        }
    };
    Ok((rt, client))
}

#[cfg(test)]
mod tests {
    use super::enforce_ws_scheme;

    #[test]
    fn wss_anywhere_allowed() {
        assert!(enforce_ws_scheme("wss://chain.orogen.network:9944").is_ok());
        assert!(enforce_ws_scheme("wss://127.0.0.1:9944").is_ok());
    }

    #[test]
    fn ws_loopback_allowed() {
        assert!(enforce_ws_scheme("ws://127.0.0.1:9944").is_ok());
        assert!(enforce_ws_scheme("ws://localhost:9944").is_ok());
        assert!(enforce_ws_scheme("ws://localhost").is_ok());
        assert!(enforce_ws_scheme("ws://[::1]:9944").is_ok());
    }

    #[test]
    fn ws_remote_rejected() {
        assert!(enforce_ws_scheme("ws://chain.orogen.network:9944").is_err());
        assert!(enforce_ws_scheme("ws://1.2.3.4:9944").is_err());
        // Spoofing attempt — host is `evil.com`, not loopback.
        assert!(enforce_ws_scheme("ws://evil.com:9944/127.0.0.1").is_err());
    }

    #[test]
    fn http_rejected() {
        assert!(enforce_ws_scheme("http://127.0.0.1:9944").is_err());
        assert!(enforce_ws_scheme("https://chain.orogen.network").is_err());
    }
}
