//! # asterism-pkcs11
//!
//! PKCS#11-backed [`asterism_core::Signer`] implementation. Talks to any
//! PKCS#11-compatible HSM through the [`cryptoki`] crate, with vendor
//! BIP-32 derivation routed through the [`HsmBackend`] trait.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │              asterism-pkcs11             │
//! │                                          │
//! │  Pkcs11Signer ──► HsmBackend ──► cryptoki│
//! │                                          │
//! └────────────────────────────┬─────────────┘
//!                              │
//!                    PKCS#11 ABI boundary
//!                              │
//!         ┌────────────────────┼────────────────────┐
//!         │                    │                    │
//!  Vendor `.so` (Utimaco)   Dev shim `.so`    Vendor `.so` (Thales)
//!  hardware BIP-32          SoftHSM + sw       hardware BIP-32
//!                            BIP-32
//! ```
//!
//! Asterism's compiled code is identical in every case. The only thing
//! that varies is which mechanism IDs the backend instructs `cryptoki` to
//! send. The dev shim's "cheating" (software BIP-32 derivation) lives
//! behind the PKCS#11 ABI boundary, not in this crate — there are no
//! `#[cfg(dev)]` paths here.
//!
//! ## Quick example
//!
//! ```ignore
//! use asterism_pkcs11::{
//!     Pkcs11Session, Pkcs11Signer, Pkcs11Config, SlotIdentifier,
//!     UtimacoBackend,
//! };
//! use bitcoin::bip32::DerivationPath;
//! use std::str::FromStr;
//!
//! let cfg = Pkcs11Config::new(
//!     "/opt/utimaco/lib/libcs_pkcs11_R3.so",
//!     SlotIdentifier::label("hsm-prod-1"),
//!     "user-pin".to_string(),
//!     DerivationPath::from_str("m/48'/0'/0'/2'")?,
//!     Box::new(UtimacoBackend),
//! );
//!
//! // 32-byte seed comes from the production key-ceremony script — it's
//! // material that is fed to the HSM exactly once and is not retained.
//! let seed: [u8; 32] = key_ceremony_seed();
//!
//! let session = Pkcs11Session::open(&cfg, &cfg.slot, /* pin */ "user-pin")?;
//! let signer = Pkcs11Signer::derive_from_seed(
//!     session,
//!     "fed-1",
//!     &cfg.derivation_path,
//!     bitcoin::Network::Bitcoin,
//!     cfg.backend,
//!     &seed,
//! )?;
//! println!("descriptor key: {}", signer.descriptor_key());
//! # fn key_ceremony_seed() -> [u8; 32] { [0u8; 32] }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Cargo features
//!
//! - `utimaco` — compiles in [`backend::UtimacoBackend`] for Utimaco
//!   Blockchain Protect HSMs.
//! - `thales` — compiles in [`backend::ThalesBackend`] for Thales
//!   ProtectServer (PTK-C) HSMs.
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

pub use asterism_core;
pub use bitcoin;
pub use cryptoki;
pub use miniscript;

#[cfg(feature = "thales")]
pub use backend::ThalesBackend;
#[cfg(feature = "utimaco")]
pub use backend::UtimacoBackend;
pub use backend::{HsmBackend, HsmBackendError, MasterKeyHandle};
pub use config::{Pkcs11Config, SlotIdentifier};
pub use error::Pkcs11Error;
pub use policy::MinimalHsmPolicy;
pub use session::Pkcs11Session;
pub use signer::Pkcs11Signer;
