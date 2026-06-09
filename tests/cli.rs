//! Integration test: drive the CLI end-to-end through `assert_cmd`.

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

fn bin(tmp: &TempDir) -> Command {
    let mut c = Command::cargo_bin("wallet-cli").unwrap();
    c.env("OROGEN_KEYSTORE", tmp.path())
        .env("OROGEN_PASSPHRASE", "test-passphrase");
    c
}

#[test]
fn new_then_list_round_trip() {
    let tmp = TempDir::new().unwrap();

    bin(&tmp)
        .args(["new", "alice"])
        .assert()
        .success()
        .stdout(contains("Created account 'alice'"))
        .stdout(contains("ss58:"))
        .stdout(contains("eth:"));

    bin(&tmp)
        .args(["list"])
        .assert()
        .success()
        .stdout(contains("alice"));

    bin(&tmp)
        .args(["address", "alice"])
        .assert()
        .success()
        .stdout(contains("ss58:"));
}

#[test]
fn sign_command_emits_hex_signature() {
    let tmp = TempDir::new().unwrap();
    bin(&tmp).args(["new", "bob"]).assert().success();
    bin(&tmp)
        .args(["sign", "bob", "0xdeadbeef"])
        .assert()
        .success()
        .stdout(contains("0x"));
}

#[test]
fn submit_extrinsic_reports_unreachable_chain_clearly() {
    // chain-node is not booted in CI; submit must surface a friendly error
    // pointing at `cargo run --bin chain-node -- --dev`.
    let tmp = TempDir::new().unwrap();
    bin(&tmp).args(["new", "alice"]).assert().success();
    bin(&tmp)
        .args([
            "submit-extrinsic",
            "0x010203",
            "--from",
            "alice",
            "--rpc-url",
            "ws://127.0.0.1:1",
        ])
        .assert()
        .failure()
        .stderr(contains("chain-node not reachable"))
        .stderr(contains("cargo run --bin chain-node"));
}

#[test]
fn submit_extrinsic_raw_mode_reports_unreachable_chain() {
    let tmp = TempDir::new().unwrap();
    // `--yes` bypasses the M-W-01 raw-extrinsic confirmation so the test can
    // reach the actual RPC connect step (where it then fails with the
    // expected unreachable-chain message).
    bin(&tmp)
        .args([
            "submit-extrinsic",
            "0x010203",
            "--raw",
            "--yes",
            "--rpc-url",
            "ws://127.0.0.1:1",
        ])
        .assert()
        .failure()
        .stderr(contains("chain-node not reachable"));
}

#[test]
fn submit_extrinsic_raw_mode_requires_confirmation() {
    // M-W-01: without `--yes` and no `YES` on stdin we must abort before
    // any RPC traffic.
    let tmp = TempDir::new().unwrap();
    bin(&tmp)
        .args([
            "submit-extrinsic",
            "0x010203",
            "--raw",
            "--rpc-url",
            "ws://127.0.0.1:1",
        ])
        .write_stdin("no\n")
        .assert()
        .failure()
        .stderr(contains("raw extrinsic confirmation"))
        .stderr(contains("aborted by user"));
}

#[test]
fn balance_reports_unreachable_chain_clearly() {
    let tmp = TempDir::new().unwrap();
    bin(&tmp).args(["new", "alice"]).assert().success();
    bin(&tmp)
        .args(["balance", "alice", "--rpc-url", "ws://127.0.0.1:1"])
        .assert()
        .failure()
        .stderr(contains("chain-node not reachable"));
}

#[test]
fn transfer_reports_unreachable_chain_clearly() {
    let tmp = TempDir::new().unwrap();
    bin(&tmp).args(["new", "alice"]).assert().success();
    bin(&tmp).args(["new", "bob"]).assert().success();
    // Pull bob's ss58 from `list` to use as a recipient address.
    let bob_out = bin(&tmp)
        .args(["address", "bob"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(bob_out.stdout).unwrap();
    let bob_ss58 = stdout
        .lines()
        .find_map(|l| l.strip_prefix("ss58: "))
        .map(|s| s.trim().to_string())
        .expect("bob ss58 in `address` output");
    bin(&tmp)
        .args([
            "transfer",
            "alice",
            &bob_ss58,
            "1000",
            "--rpc-url",
            "ws://127.0.0.1:1",
        ])
        .assert()
        .failure()
        .stderr(contains("chain-node not reachable"));
}

#[test]
fn heartbeat_test_signs_payload() {
    let tmp = TempDir::new().unwrap();
    bin(&tmp).args(["new", "carol"]).assert().success();
    let out = bin(&tmp)
        .args([
            "heartbeat-test",
            "carol",
            "--gpu-model",
            "H100-SXM-80GB",
            "--free-kv-blocks",
            "1024",
            "--endpoint-url",
            "https://operator.example",
            "--model",
            "mock-model-7b",
            "--receipt-pubkey-hex",
            "ababcdefababcdefababcdefababcdefababcdefababcdefababcdefababcdef",
        ])
        .assert()
        .success()
        .stdout(contains("heartbeat_json"))
        .stdout(contains("signature"))
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let body = parsed["heartbeat_json"].as_str().unwrap();
    assert!(body.contains("operator_ss58"));
    assert!(body.contains("endpoint_url"));
    assert!(body.contains("receipt_pubkey_hex"));
}

#[test]
fn duplicate_account_is_rejected() {
    let tmp = TempDir::new().unwrap();
    bin(&tmp).args(["new", "dup"]).assert().success();
    bin(&tmp).args(["new", "dup"]).assert().failure();
}
