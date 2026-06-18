pub mod address;
pub mod balance;
pub mod heartbeat;
pub mod import;
pub mod list;
pub mod new;
pub mod register_operator;
pub mod sign;
pub mod stake;
pub mod submit;
pub mod transfer;

/// Read a passphrase. Order (security audit M-W-02 — interactive prompt is
/// the canonical path; `--passphrase` / env are explicit opt-ins so they do
/// not appear in shell history or process listings by accident):
/// 1. `--passphrase <value>` flag (CI / scripted use).
/// 2. `OROGEN_PASSPHRASE` env var (CI / scripted use).
/// 3. Interactive `rpassword` TTY prompt — primary path for humans. Reads
///    without echoing; falls back to a helpful error if there is no TTY
///    (and neither flag nor env is set).
pub fn resolve_passphrase(flag: Option<&str>) -> anyhow::Result<String> {
    if let Some(p) = flag {
        return Ok(p.to_string());
    }
    if let Ok(p) = std::env::var("OROGEN_PASSPHRASE") {
        return Ok(p);
    }
    // Interactive prompt — never echoes the passphrase.
    match rpassword::prompt_password("keystore passphrase: ") {
        Ok(p) => Ok(p),
        Err(e) => Err(anyhow::anyhow!(
            "passphrase not provided and no TTY for interactive prompt ({e}); \
             pass --passphrase or set OROGEN_PASSPHRASE"
        )),
    }
}

/// Read a BIP-39 mnemonic. Order mirrors `resolve_passphrase` — the mnemonic
/// derives every key and is strictly more sensitive than the passphrase, so it
/// gets the same protection (security audit M-W-05; the prior `--mnemonic`
/// required flag leaked the full 24-word phrase to argv, `ps`, and shell
/// history):
/// 1. `--mnemonic <value>` flag — EXPLICIT OPT-IN, documented as unsafe. Only
///    use for scripted/CI imports where you accept the phrase is visible in the
///    process listing and shell history.
/// 2. `OROGEN_MNEMONIC` env var (CI / scripted use).
/// 3. Interactive `rpassword` TTY prompt — primary path for humans. Reads
///    without echoing and asks twice to confirm; errors out if there is no TTY
///    (and neither flag nor env is set).
pub fn resolve_mnemonic(flag: Option<&str>) -> anyhow::Result<String> {
    if let Some(m) = flag {
        return Ok(m.to_string());
    }
    if let Ok(m) = std::env::var("OROGEN_MNEMONIC") {
        return Ok(m);
    }
    // Interactive prompt — never echoes the mnemonic.
    let m = rpassword::prompt_password("mnemonic phrase: ")?;
    let confirm = rpassword::prompt_password("confirm mnemonic phrase: ")?;
    if m != confirm {
        return Err(anyhow::anyhow!("mnemonic phrases did not match"));
    }
    Ok(m)
}
