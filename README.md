# asterism-pkcs11

> PKCS#11-backed [`Signer`](../asterism-core/src/signer.rs) implementation for
> the Emerald multi-signature custody platform.

`asterism-pkcs11` is the Hardware Security Module (HSM) backend for
[`asterism-core`]. It implements both `asterism_core::Signer` (so the signer
participates in federation construction, descriptor building, and recovery)
and `bdk_wallet::signer::TransactionSigner` (so BDK can dispatch PSBT signing
to it transparently).

It speaks PKCS#11 via [`cryptoki`] and works with any compliant token —
[SoftHSMv2] for development, YubiHSM 2, AWS CloudHSM, Thales Luna, etc. for
production.

## Design priorities

This crate honors the priorities laid out in `.cursorrules`:

1. **Developer ergonomics** — generate a key, build a `Pkcs11Signer`, and
   compose it into a `Federation` in fewer than 20 lines (see example below).
2. **Ecosystem leverage** — uses `cryptoki` for the PKCS#11 wire format,
   `bitcoin` and `miniscript` for everything cryptographic, and
   `bdk_wallet`'s `TransactionSigner` trait for signing dispatch. No
   parallel implementations of any of those.
3. **Focused responsibility** — this crate manages session lifecycle, HSM
   key/data objects, ECDSA signing with low-S normalization, and the
   `MinimalHsmPolicy` defense-in-depth layer. It does **not** manage chain
   sync, UTXOs, or coin selection; that's the consumer's responsibility
   (BDK's `Wallet`).
4. **Compile-time safety** — `Pkcs11Signer` is `Send + Sync` even though
   `cryptoki::Session` is `!Sync`; an internal `Arc<Mutex<...>>` enforces
   single-session access while keeping public-facing accessors lock-free.
5. **Pragmatic delegation** — implements BDK's `TransactionSigner`, so
   integrators register a `Pkcs11Signer` with `Wallet::add_signer()` and
   call `Wallet::sign()` exactly as they would for any software signer.
6. **Security & auditability** — private keys never leave the HSM
   (`CKA_EXTRACTABLE=false`). The optional `MinimalHsmPolicy` enforces
   per-transaction limits, signature-rate ceilings, and destination
   whitelists at the HSM layer, surviving any compromise of the
   application server.
7. **Maintainability** — pluggable [`Bip32DerivationStrategy`] keeps the v1
   `FixedKey` (single-key-per-HSM) implementation simple while leaving
   room for `HsmNativeBip32` and `SoftwareTweakDev` (feature-gated) without
   API churn.

## Module layout

```
src/
├── lib.rs              re-exports + crate-level doc
├── config.rs           Pkcs11Config, SlotIdentifier (Label / SlotId)
├── session.rs          Pkcs11Session (load library, resolve slot, login, R/W session)
├── derivation.rs       Bip32DerivationStrategy: FixedKey, HsmNativeBip32, SoftwareTweakDev
├── ecdsa.rs            sign_with_low_s (BIP-146 canonicalization on top of CKM_ECDSA)
├── key_ops.rs          generate_key, find_key_by_label, derive_xpub, delete_key,
│                       SignerKeyMaterial (chain code + metadata persisted on token)
├── policy.rs           MinimalHsmPolicy + SigRateCounter, persisted as CKO_DATA objects
├── signer.rs           Pkcs11Signer impl asterism_core::Signer
│                       + impl bdk_wallet::signer::TransactionSigner
└── error.rs            Pkcs11Error + From<Pkcs11Error> for asterism_core::SignerError
```

## On-token object model (Fixed strategy, default)

Each `Pkcs11Signer` materializes as four objects on its token, all with
`CKA_TOKEN=true`, prefixed with `asterism/v1/{label}/`:

| Object         | Class                | Notes                                                               |
| -------------- | -------------------- | ------------------------------------------------------------------- |
| `…/priv`       | `CKO_PRIVATE_KEY`    | secp256k1, `CKA_SIGN=true`, `CKA_EXTRACTABLE=false`                 |
| `…/pub`        | `CKO_PUBLIC_KEY`     | matching public key (fast lookup; `CKA_EC_POINT` carries the point) |
| `…/material`   | `CKO_DATA`           | JSON-serialized `SignerKeyMaterial` (chain code, fingerprint, path) |
| `…/policy`     | `CKO_DATA` (opt.)    | JSON-serialized `MinimalHsmPolicy`                                  |
| `…/sigrate`    | `CKO_DATA` (opt.)    | JSON-serialized `SigRateCounter` (last-hour signing timestamps)     |

Storing the chain code on-token is safe (the chain code is *public*) and
makes the cryptographic identity of a signer recoverable purely from HSM
state — no external configuration database required.

## A 20-line example: connect, generate, build a federation

```rust,ignore
use asterism_core::{Federation, NetworkType, Signer};
use asterism_pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier};
use bitcoin::bip32::DerivationPath;
use std::str::FromStr;

let cfg = Pkcs11Config::from_env()?;
let session = Pkcs11Session::open(
    &cfg,
    &SlotIdentifier::label("asterism-test"),
    "test-pin-9999",
)?;

let path = DerivationPath::from_str("m/48'/1'/0'/2'")?;
let signer = Pkcs11Signer::generate(session, "fed-1", &path, bitcoin::Network::Testnet)?;
println!("xpub:        {}", signer.xpub());
println!("fingerprint: {}", signer.fingerprint());

// Combine N signers (one per HSM) into a federation.
let signers: Vec<Box<dyn Signer>> = vec![Box::new(signer) /* …, more HSMs … */];
let federation: Federation =
    Federation::new(1, signers, NetworkType::Bitcoin(bitcoin::Network::Testnet))?;
println!("descriptor:  {}", federation.descriptor_string());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Signing flow (BDK integration)

```text
asterism_core::SigningCoordinator (Software path)
    │
    ▼
bdk_wallet::Wallet::sign  ──►  walks `partial_sigs`, dispatches to TransactionSigner
    │                          impls registered via `Wallet::add_signer()`
    ▼
Pkcs11Signer::sign_transaction
    │
    ├── load policy → check per-tx limit + destination whitelist
    ├── for each input matching our fingerprint:
    │       compute BIP-143 sighash
    │       sign via Bip32DerivationStrategy::sign_input
    │       normalize_s + insert as bitcoin::ecdsa::Signature into partial_sigs
    └── increment sig-rate counter atomically (if max_signatures_per_hour set)
```

The signer never finalizes the PSBT itself; once threshold partial
signatures are collected, the consumer calls `Wallet::finalize_psbt()`
(which `asterism_core::SigningCoordinator::finalize` wraps).

## Cargo features

- `default = []` — minimal v1 build with `FixedKey` derivation only.
- `integration` — enables the `tests/integration.rs` suite (requires a
  running SoftHSMv2 with the `asterism-test` token and the dev tokens
  initialized per `design_docs/README.md`).
- `dev-derivation` — enables [`derivation::SoftwareTweakDev`], a
  development-only strategy that derives child *private* keys in software.
  **Violates the security boundary**; never enable in production.
- `node-tests` — enables `tests/node_pkcs11_cross_check.rs`, which builds
  HSM-backed federations and cross-validates descriptors / addresses
  against a running Bitcoin Core node via `BITCOIN_RPC_*` from `.env`.

## Testing

```bash
# Unit tests (no HSM required):
cargo test -p asterism-pkcs11

# Integration tests (require SoftHSMv2 with asterism-test + dev tokens):
cargo test -p asterism-pkcs11 --features integration -- --test-threads=1

# HSM + bitcoind cross-validation (also requires BITCOIN_RPC_* in .env):
cargo test -p asterism-pkcs11 --features "integration node-tests" \
  --test node_pkcs11_cross_check -- --nocapture

# Doc build:
cargo doc -p asterism-pkcs11 --no-deps
```

The integration tests read HSM credentials from `../asterism-core/.env`
(via `dotenvy`) and serialize access via `serial_test::serial` so the
shared SoftHSMv2 token state is stable across runs. `node-tests` skip
gracefully when the bitcoind RPC endpoint is unreachable.

## License

MIT OR Apache-2.0

[`asterism-core`]: ../asterism-core/
[`cryptoki`]: https://crates.io/crates/cryptoki
[SoftHSMv2]: https://github.com/opendnssec/SoftHSMv2
