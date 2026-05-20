//! On-disk keystore for `wallet-cli`.
//!
//! Each account is stored as a single JSON file:
//!
//! ```json
//! {
//!   "name": "alice",
//!   "scheme": "sr25519+secp256k1",
//!   "ss58":   "5GrwvaEF...",
//!   "eth":    "0xabc...",
//!   "ciphertext_b64": "...",
//!   "salt_b64": "...",
//!   "nonce_b64": "...",
//!   "kdf": "argon2id",
//!   "created_ms": 1747353600000
//! }
//! ```
//!
//! `ciphertext` is `ChaCha20-Poly1305(plaintext = mnemonic.utf8(), key = Argon2id(passphrase, salt))`.
//! Plaintext never lives on disk; passphrase is prompted on each operation
//! that needs the private key.
//!
//! The format is intentionally simple; a v2 keystore (post-audit) will add
//! a `kdf_params` block and a hardware-attestation field per the gate
//! 10.3 hardening checklist.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use argon2::{Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use wallet_sdk_core::keys::{EthKeypair, Mnemonic, Sr25519Keypair};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountFile {
    pub name: String,
    pub scheme: String,
    pub ss58: String,
    pub eth: String,
    pub ciphertext_b64: String,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub kdf: String,
    pub created_ms: u64,
}

pub struct Keystore {
    root: PathBuf,
}

impl Keystore {
    /// Open (and create if missing) the keystore directory.
    ///
    /// If `override_dir` is `Some`, that path is used verbatim; otherwise the
    /// XDG-compliant `~/.config/orogen/wallet-cli/keys/` location is used.
    pub fn open(override_dir: Option<PathBuf>) -> Result<Self> {
        let root = if let Some(p) = override_dir {
            p
        } else {
            let proj = directories::ProjectDirs::from("network", "orogen", "wallet-cli")
                .ok_or_else(|| anyhow!("could not resolve config home"))?;
            proj.config_dir().join("keys")
        };
        fs::create_dir_all(&root)
            .with_context(|| format!("creating keystore dir {root:?}"))?;
        Ok(Self { root })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn account_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.json"))
    }

    pub fn list(&self) -> Result<Vec<AccountFile>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let contents = fs::read_to_string(&path)?;
            let file: AccountFile = serde_json::from_str(&contents)
                .with_context(|| format!("parsing keystore file {path:?}"))?;
            out.push(file);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn load(&self, name: &str) -> Result<AccountFile> {
        let path = self.account_path(name);
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("reading {path:?}"))?;
        Ok(serde_json::from_str(&contents)?)
    }

    pub fn save_new(
        &self,
        name: &str,
        mnemonic: &Mnemonic,
        passphrase: &str,
    ) -> Result<AccountFile> {
        let path = self.account_path(name);
        if path.exists() {
            return Err(anyhow!("account '{name}' already exists at {path:?}"));
        }

        // Derive addresses.
        let sr = Sr25519Keypair::from_mnemonic(mnemonic)?;
        let eth = EthKeypair::from_mnemonic(mnemonic)?;
        let ss58 = wallet_sdk_core::addresses::sr25519_to_ss58(&sr);
        let eth_addr = wallet_sdk_core::addresses::eth_to_address(&eth);

        // Encrypt mnemonic.
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let key = derive_key(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let phrase = mnemonic.phrase();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), phrase.as_bytes())
            .map_err(|e| anyhow!("encrypt failed: {e}"))?;

        let file = AccountFile {
            name: name.to_string(),
            scheme: "sr25519+secp256k1".to_string(),
            ss58,
            eth: eth_addr,
            ciphertext_b64: B64.encode(&ciphertext),
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(nonce_bytes),
            kdf: "argon2id".to_string(),
            created_ms: now_ms(),
        };

        fs::write(&path, serde_json::to_vec_pretty(&file)?)
            .with_context(|| format!("writing {path:?}"))?;

        // Zeroize phrase string (best effort — Rust String drops alloc).
        let mut z = phrase;
        z.zeroize();

        Ok(file)
    }

    /// Decrypt and return the underlying mnemonic.
    pub fn unlock(&self, name: &str, passphrase: &str) -> Result<Mnemonic> {
        let file = self.load(name)?;
        let salt = B64.decode(&file.salt_b64)?;
        let nonce_bytes = B64.decode(&file.nonce_b64)?;
        let ciphertext = B64.decode(&file.ciphertext_b64)?;

        let key = derive_key(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| anyhow!("decrypt failed (wrong passphrase or corrupt keystore)"))?;
        let phrase = String::from_utf8(plaintext)?;
        Ok(Mnemonic::from_phrase(&phrase)?)
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    // Argon2id parameters (security audit M-W-03):
    //
    //   m_cost = 19_456 KiB  (~19 MiB)
    //   t_cost = 2 iterations
    //   p_cost = 1 lane
    //
    // This matches the OWASP 2024 Password Storage Cheat Sheet first profile
    // ("Argon2id with a minimum configuration of 19 MiB of memory, an
    // iteration count of 2, and 1 degree of parallelism"). Keystore unlock
    // takes <1 s on commodity hardware. The alternative OWASP profile
    // (46 MiB, t=1, p=1) is also acceptable; we picked the lower-memory one
    // so the CLI stays usable on constrained CI runners and embedded testbeds.
    //
    // We do not use the PHC string format because we want a raw 32-byte key
    // for the ChaCha20-Poly1305 cipher.
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2 derive: {e}"))?;
    Ok(out)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
