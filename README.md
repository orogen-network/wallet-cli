# wallet-cli

Command-line wallet for Orogen operators and validators. It manages accounts
(an sr25519 hotkey plus a derived EVM-bridge key from a single BIP-39 mnemonic),
signs payloads, and submits on-chain extrinsics against an Orogen node.

Accounts live under `~/.config/orogen/wallet-cli/keys/`, encrypted at rest with
an Argon2id-derived ChaCha20-Poly1305 key. The mnemonic plaintext never touches
disk; the passphrase is prompted on each operation that needs the private key.

## Build

```sh
git clone https://github.com/orogen-network/wallet-cli.git
cd wallet-cli
cargo build --release
./target/release/wallet-cli --help
```

## Network configuration

Commands that talk to a node take an RPC URL. Resolution order:

1. `--rpc-url <url>` flag
2. `OROGEN_RPC_URL` environment variable
3. default `ws://127.0.0.1:9944` (a local dev node)

To use the live Forge testnet, set:

```sh
export OROGEN_RPC_URL=wss://forge-rpc.orogen.network
```

The keystore directory can be overridden with `--keystore <dir>` or the
`OROGEN_KEYSTORE` environment variable.

## Quickstart (live Forge testnet)

```sh
export OROGEN_RPC_URL=wss://forge-rpc.orogen.network

# 1. Create an account and print its addresses.
wallet-cli new my-operator
wallet-cli address my-operator

# 2. Fund the ss58 address from the public faucet (testnet OROG, low-cap).
curl -X POST https://faucet.orogen.network/drip-public \
  -H 'Content-Type: application/json' \
  -d '{"recipient":"<ss58 address from step 1>"}'
wallet-cli balance my-operator

# 3. Register as an operator. --stake is in plancks (atomic units);
#    MinStake on Forge is 1_000_000_000_000 = 1 OROG.
wallet-cli register-operator my-operator \
  --stake 1000000000000 \
  --attestation-hash 0x0000000000000000000000000000000000000000000000000000000000000000

# 4. Submit an on-chain liveness heartbeat for the current epoch.
wallet-cli heartbeat-test my-operator --submit --epoch <current-epoch>

# 5. Advertise the worker to the public gateway. Use the receipt public key
#    printed by `python -m infer_worker_vllm --generate-keypair`.
wallet-cli heartbeat-test my-operator \
  --endpoint-url https://<your-worker-host> \
  --model mock-model-7b \
  --price-per-million-tokens 1500 \
  --receipt-pubkey-hex <64-hex ed25519 public key> \
  | curl -sS -X POST https://gateway.orogen.network/v1/operator/heartbeat \
      -H 'Content-Type: application/json' \
      -d @-
```

Forge is a test-mode preview: the gateway runs in test mode, the attestation
service issues mock quotes, and the faucet is low-cap. See
<https://docs.orogen.network/start/forge-testnet> for the full caveats.

## Subcommands

Most commands take the account `name` as the first positional argument and
prompt for the passphrase unless `--passphrase <pw>` is supplied.

| Command | Purpose |
|---|---|
| `new <name>` | Create a new account (sr25519 + EVM-bridge key from one mnemonic). |
| `import <name> --mnemonic "<words>"` | Import an existing account from a BIP-39 mnemonic. |
| `list` | List accounts in the keystore. |
| `address <name>` | Print the ss58 and EVM addresses for an account. |
| `balance <account>` | Query the free balance from `System::Account` over RPC. |
| `transfer <from> <to> --amount <plancks>` | Submit `balances.transfer_keep_alive`. |
| `sign <name> <payload_hex>` | Sign an arbitrary hex payload with the account hotkey. |
| `submit-extrinsic <payload_hex>` | Submit an extrinsic. Wraps the payload in `system.remark` by default; `--raw` forwards a pre-encoded SCALE blob via `author_submitExtrinsic`. |
| `register-operator <name> --stake <plancks> [--attestation-hash 0x..]` | Submit `OperatorStake::register(stake, attestation_hash)`. |
| `heartbeat-test <name>` | Print a domain-signed RFC-0003 heartbeat envelope for public gateway ingest. With `--submit --epoch <n>` it submits the on-chain `OperatorStake::heartbeat` extrinsic instead. |
| `stake <name> --amount <plancks>` | Produce a domain-signed stake payload (signature only; no on-chain submission). |

### Common flags

- `--rpc-url <url>` / `OROGEN_RPC_URL`, node endpoint for commands that talk to chain.
- `--keystore <dir>` / `OROGEN_KEYSTORE`, keystore directory override.
- `--passphrase <pw>`, supply the unlock passphrase non-interactively.

### register-operator

```sh
wallet-cli register-operator <name> \
  --stake <plancks> \
  --attestation-hash 0x<h256> \
  --rpc-url wss://forge-rpc.orogen.network
```

- `<name>` is the keystore account name (the stake-backed hotkey).
- `--stake` is in plancks and must be `>=` the runtime `MinStake`
  (`1_000_000_000_000` = 1 OROG on Forge). The stake is reserved for the
  lifetime of the registration.
- `--attestation-hash` is an `H256` (hex, optional `0x` prefix). It defaults to
  the zero hash for testnet bring-up, where it is not yet validated on-chain.

### heartbeat-test

```sh
# On-chain liveness heartbeat:
wallet-cli heartbeat-test <name> --submit --epoch <n>
```

`--submit` sends `OperatorStake::heartbeat(epoch_number, capabilities_summary_hash,
attestation_report_hash)`. The runtime requires `epoch >= last_heartbeat_epoch`
and an advance of at most `MaxHeartbeatEpochAdvance` (1 on Forge), so pass the
current epoch. `--capabilities-hash` and `--attestation-hash` default to the
zero hash. Without `--submit`, the command prints a signed JSON envelope for
`POST /v1/operator/heartbeat` and does not touch the chain. Include
`--endpoint-url`, one or more `--model` values, and `--receipt-pubkey-hex` when
you want the public gateway to route completions to the worker and verify its
RFC-0001 receipts.

## Notes

- Coldkey/hotkey separation, hardware attestation fields, and a v2 keystore
  format are planned hardening items.
- The production heartbeat loop runs in `worker-control-plane`;
  `heartbeat-test --submit` is for operator-side verification and manual
  submission.
