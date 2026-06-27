# emvault-pkcs11

> PKCS#11-backed [`Signer`](https://github.com/gmikeska/emvault-core)
> implementation for the Emerald multi-signature custody platform.

`emvault-pkcs11` is the Hardware Security Module (HSM) backend for
[`emvault-core`]. It implements both `emvault_core::Signer` (so the signer
participates in federation construction, descriptor building, and recovery)
and `bdk_wallet::signer::TransactionSigner` (so BDK can dispatch PSBT
signing to it transparently).

It speaks PKCS#11 via [`cryptoki`] and works with any compliant token. The
vendor-specific BIP-32 mechanism IDs and attribute IDs are abstracted by
the [`HsmBackend`] trait. Production-HSM `HsmBackend` implementations
live in their own downstream crates (one per vendor SDK) so each
deployment pulls in only the vendor it actually uses, while the matching
development backend (`DevBackend`) lives in the separate
[`emvault-dev-signer`] crate so dev-only code never lands in production
builds.

## Architecture

```
┌─────────────────────────────────────────┐
│              emvault-pkcs11             │
│                                          │
│  Pkcs11Signer ──► HsmBackend ──► cryptoki│
│                                          │
└────────────────────────────┬─────────────┘
                             │
                   PKCS#11 ABI boundary
                             │
            ┌────────────────┴────────────────┐
            │                                 │
     Vendor `.so` (prod)              Dev shim `.so`
     hardware BIP-32                  SoftHSM + sw BIP-32
```

EmVault's compiled code is identical in every case. The only thing that
varies is which mechanism IDs the backend instructs `cryptoki` to send.
The dev shim's "cheating" (software BIP-32 derivation behind the PKCS#11
ABI) is invisible to this crate.

## Design priorities

This crate honors the priorities laid out in `.cursorrules`:

1. **Developer ergonomics** — derive a signer, build a `Pkcs11Signer`, and
   compose it into a `Federation` in fewer than 20 lines (see example
   below).
2. **Ecosystem leverage** — uses `cryptoki` for the PKCS#11 wire format,
   `bitcoin` and `miniscript` for everything cryptographic, and
   `bdk_wallet`'s `TransactionSigner` trait for signing dispatch. No
   parallel implementations of any of those.
3. **Focused responsibility** — this crate manages session lifecycle,
   ECDSA signing with low-S normalization, the `MinimalHsmPolicy`
   defense-in-depth layer, and the `HsmBackend` vendor-mechanism seam. It
   does **not** manage chain sync, UTXOs, or coin selection; that's the
   consumer's responsibility (BDK's `Wallet`).
4. **Compile-time safety** — `Pkcs11Signer` is `Send + Sync` even though
   `cryptoki::Session` is `!Sync`; an internal `Arc<Mutex<...>>` enforces
   single-session access while keeping public-facing accessors lock-free.
5. **Pragmatic delegation** — implements BDK's `TransactionSigner`, so
   integrators register a `Pkcs11Signer` with `Wallet::add_signer()` and
   call `Wallet::sign()` exactly as they would for any software signer.
6. **Security & auditability** — private keys never leave the HSM.
   EmVault's compiled code never sees plaintext key material; the
   `derive_from_seed` constructor passes the seed straight to the HSM via
   `C_DeriveKey`. The optional `MinimalHsmPolicy` enforces per-transaction
   limits, signature-rate ceilings, and destination whitelists at the
   HSM layer, surviving any compromise of the application server.
7. **Maintainability** — the `HsmBackend` trait isolates vendor-specific
   knowledge to a single small surface (six accessor methods plus, for
   vendors with non-standard mechanism parameter struct layouts, four
   default method bodies that may be overridden).

## Module layout

```
src/
├── lib.rs              re-exports + crate-level doc
├── config.rs           Pkcs11Config, SlotIdentifier (Label / SlotId)
├── session.rs          Pkcs11Session (load library, resolve slot, login, R/W session)
├── backend/            HsmBackend trait (vendor backends live in their own crates)
│   └── mod.rs          HsmBackend, MasterKeyHandle, HsmBackendError, default impls
├── ecdsa.rs            sign_with_low_s (BIP-146 canonicalization on top of CKM_ECDSA)
├── key_ops.rs          find_key_by_label, delete_key, label helpers, EC point DER helpers
├── policy.rs           MinimalHsmPolicy + SigRateCounter, persisted as CKO_DATA objects
├── signer.rs           Pkcs11Signer impl emvault_core::Signer
│                       + impl bdk_wallet::signer::TransactionSigner
└── error.rs            Pkcs11Error + From<Pkcs11Error> for emvault_core::SignerError
```

## On-token object model

Each `Pkcs11Signer` materializes as objects on its token, all with
`CKA_TOKEN=true`, prefixed with `emvault/v1/{label}/`:

| Object         | Class                | Notes                                                               |
| -------------- | -------------------- | ------------------------------------------------------------------- |
| `…/priv`       | `CKO_PRIVATE_KEY`    | secp256k1, `CKA_SIGN=true`, `CKA_EXTRACTABLE=false`                 |
| `…/policy`     | `CKO_DATA` (opt.)    | JSON-serialized `MinimalHsmPolicy`                                  |
| `…/sigrate`    | `CKO_DATA` (opt.)    | JSON-serialized `SigRateCounter` (last-hour signing timestamps)     |

The chain code and other BIP-32 metadata live as **vendor-specific
attributes on the private key object** (mediated by `HsmBackend`). On a
production HSM these are stored inside the secure boundary; the dev shim
keeps a parallel companion `CKO_SECRET_KEY` that mirrors the BIP-32
serialization, but that detail is invisible to this crate.

## A 20-line example: connect, derive, build a federation

The example below uses the development backend; for production, replace
`DevBackend` with a vendor-supplied implementation from the appropriate
downstream crate, point `library_path` at the vendor's `.so`, and pass a
real 64-byte BIP-32 seed instead of the empty slice.

```rust,ignore
use emvault_core::{Federation, NetworkType, Signer};
use emvault_dev_signer::DevBackend;
use emvault_pkcs11::{
    Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier,
};
use bitcoin::bip32::DerivationPath;
use std::str::FromStr;

let cfg = Pkcs11Config::new(
    "/path/to/libemvault_dev_hsm.so",
    SlotIdentifier::label("dev-app-1"),
    "user-pin".to_string(),
    DerivationPath::from_str("m/48'/1'/0'/2'")?,
    Box::new(DevBackend),
);

let session = Pkcs11Session::open(&cfg, &cfg.slot, "user-pin")?;
// Empty seed: the dev shim looks up the slot's preconfigured BIP-39
// mnemonic. Production backends should pass a 64-byte BIP-32 seed.
let signer = Pkcs11Signer::derive_from_seed(
    session,
    "fed-1",
    &cfg.derivation_path,
    bitcoin::Network::Regtest,
    cfg.backend,
    &[],
)?;

let signers: Vec<Box<dyn Signer>> = vec![Box::new(signer) /* …, more HSMs … */];
let federation: Federation =
    Federation::new(1, signers, NetworkType::Bitcoin(bitcoin::Network::Regtest))?;
println!("descriptor: {}", federation.descriptor_string());
# Ok::<(), Box<dyn std::error::Error>>(())
```

For convenience scripts that wire SoftHSM tokens, slot allocation, and a
default federation in one shot, use [`emvault-dev-signer`]'s
`setup_dev_federation()` helper.

## Signing flow (BDK integration)

```text
emvault_core::SigningCoordinator (Software path)
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
    │       derive child key via HsmBackend (`/change/idx` from the federation key)
    │       sign with CKM_ECDSA, normalize_s
    │       insert as bitcoin::ecdsa::Signature into partial_sigs
    │       destroy session-only child handle
    └── increment sig-rate counter atomically (if max_signatures_per_hour set)
```

The signer never finalizes the PSBT itself; once threshold partial
signatures are collected, the consumer calls `Wallet::finalize_psbt()`
(which `emvault_core::SigningCoordinator::finalize` wraps).

## Cargo features

- `default = []` — minimal v1 build (vendor-agnostic core only).
- `elements` — adds Elements/Liquid signing on top of `Pkcs11Signer`.
- `integration` — enables the `tests/integration.rs` suite (requires a
  running PKCS#11 token; see `../emvault-dev-signer` for the dev path).
- `node-tests` — enables `tests/node_pkcs11_cross_check.rs`, which
  builds HSM-backed federations and cross-validates descriptors /
  addresses against a running Bitcoin Core node via `BITCOIN_RPC_*`
  from `.env`.

## Testing

```bash
# Unit tests (no HSM required):
cargo test -p emvault-pkcs11

# Integration tests (require a PKCS#11 token; the recommended dev path is
# the libemvault_dev_hsm.so shim driven by emvault-dev-signer):
cargo test -p emvault-pkcs11 --features integration -- --test-threads=1

# HSM + bitcoind cross-validation (also requires BITCOIN_RPC_* in .env):
cargo test -p emvault-pkcs11 --features "integration node-tests" \
  --test node_pkcs11_cross_check -- --nocapture

# Doc build:
cargo doc -p emvault-pkcs11 --no-deps
```

Integration tests read PKCS#11 credentials from `../emvault-core/.env`
(via `dotenvy`) and serialize access via `serial_test::serial` so the
shared token state is stable across runs. `node-tests` skip gracefully
when the bitcoind RPC endpoint is unreachable.

## License

MIT OR Apache-2.0

[`emvault-core`]: https://github.com/gmikeska/emvault-core
[`emvault-dev-signer`]: https://github.com/gmikeska/emvault-dev-signer
[`cryptoki`]: https://crates.io/crates/cryptoki
[`HsmBackend`]: src/backend/mod.rs
