//! # emvault-pkcs11
//!
//! PKCS#11-backed [`emvault_core::Signer`] implementation. Talks to any
//! PKCS#11-compatible HSM through the [`cryptoki`] crate, with vendor
//! BIP-32 derivation routed through the [`HsmBackend`] trait.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │              emvault-pkcs11             │
//! │                                          │
//! │  Pkcs11Signer ──► HsmBackend ──► cryptoki│
//! │                                          │
//! └────────────────────────────┬─────────────┘
//!                              │
//!                    PKCS#11 ABI boundary
//!                              │
//!             ┌────────────────┴────────────────┐
//!             │                                 │
//!      Vendor `.so` (prod)              Dev shim `.so`
//!      hardware BIP-32                  SoftHSM + sw BIP-32
//! ```
//!
//! EmVault's compiled code is identical in every case. The only thing
//! that varies is which mechanism IDs the backend instructs `cryptoki` to
//! send. The dev shim's "cheating" (software BIP-32 derivation) lives
//! behind the PKCS#11 ABI boundary, not in this crate — there are no
//! `#[cfg(dev)]` paths here.
//!
//! Production-HSM `HsmBackend` implementations live in their own
//! downstream crates (one per vendor SDK); see those crates for usage
//! examples. The development backend ships in
//! [`emvault-dev-signer`](https://docs.rs/emvault-dev-signer) and is the
//! basis for the example below.
//!
//! ## Quick example (development backend)
//!
//! ```ignore
//! use emvault_dev_signer::DevBackend;
//! use emvault_pkcs11::{
//!     Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier,
//! };
//! use bitcoin::bip32::DerivationPath;
//! use std::str::FromStr;
//!
//! let cfg = Pkcs11Config::new(
//!     "/path/to/libemvault_dev_hsm.so",
//!     SlotIdentifier::label("dev-app-1"),
//!     "user-pin".to_string(),
//!     DerivationPath::from_str("m/48'/1'/0'/2'")?,
//!     Box::new(DevBackend),
//! );
//!
//! let session = Pkcs11Session::open(&cfg, &cfg.slot, /* pin */ "user-pin")?;
//! // Empty seed: the dev shim looks up the slot's preconfigured BIP-39
//! // mnemonic and derives the seed itself. Production backends should
//! // pass the 64-byte BIP-32 seed material directly.
//! let signer = Pkcs11Signer::derive_from_seed(
//!     session,
//!     "fed-1",
//!     &cfg.derivation_path,
//!     bitcoin::Network::Regtest,
//!     cfg.backend,
//!     &[],
//! )?;
//! println!("descriptor key: {}", signer.descriptor_key());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Cargo features
//!
//! - `elements` — adds Elements/Liquid signing on top of `Pkcs11Signer`
//!   (HSM ECDSA path is identical; CT-specific operations stay
//!   software-side via LWK).
//! - `integration` — gates the `tests/integration.rs` suite (requires a
//!   running PKCS#11 token).
//! - `node-tests` — gates RPC-driven tests against an external
//!   `bitcoind`.

#![warn(missing_docs)]
#![deny(unsafe_code)]
#![allow(
    // chatty on every getter/builder; not a footgun in this codebase
    clippy::must_use_candidate,
    // const-fn surface area is still evolving in stable Rust
    clippy::missing_const_for_fn,
)]

pub mod backend;
pub mod config;
pub mod ecdsa;
#[cfg(feature = "elements")]
pub mod elements;
pub mod error;
pub mod key_ops;
pub mod policy;
pub mod session;
pub mod signer;

pub use bitcoin;
pub use cryptoki;
pub use emvault_core;
pub use miniscript;

pub use backend::{HsmBackend, HsmBackendError, MasterKeyHandle};
pub use config::{Pkcs11Config, SlotIdentifier};
pub use error::Pkcs11Error;
pub use policy::MinimalHsmPolicy;
pub use session::Pkcs11Session;
pub use signer::{NetworkPatchedSigner, Pkcs11Signer};
