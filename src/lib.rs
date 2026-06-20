//! # asterism-pkcs11
//!
//! PKCS#11-backed [`asterism_core::Signer`] implementation. Talks to any
//! PKCS#11-compatible HSM (`SoftHSMv2` for development; `YubiHSM`, Thales
//! Luna, AWS `CloudHSM`, etc. for production) via the [`cryptoki`] crate.
//!
//! Each [`Pkcs11Signer`] represents a single HSM token holding one secp256k1
//! keypair plus chain-code and metadata stored as `CKO_DATA` objects. The
//! signer participates in [`Federation`](asterism_core::Federation)s built by
//! `asterism-core`.
//!
//! ## Quick example
//!
//! ```ignore
//! use asterism_pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier};
//! use bitcoin::bip32::DerivationPath;
//! use std::str::FromStr;
//!
//! let cfg = Pkcs11Config::from_env()?;
//! let session = Pkcs11Session::open(
//!     &cfg,
//!     &SlotIdentifier::label("asterism-test"),
//!     "test-pin-9999",
//! )?;
//! let path = DerivationPath::from_str("m/48'/1'/0'/2'")?;
//! let signer = Pkcs11Signer::generate(session, "fed-1", &path, bitcoin::Network::Testnet)?;
//! println!("descriptor key: {}", signer.descriptor_key());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## v1 scope
//!
//! - **Fixed-key BIP32 derivation strategy** is the only strategy enabled by
//!   default. Each signer holds one key; the federation descriptor uses raw
//!   pubkeys (`DescriptorPublicKey::Single`) rather than ranged xpubs. This
//!   matches `SoftHSMv2`'s capabilities and the institutional-custody model.
//! - [`HsmNativeBip32`] is provided for production HSMs that advertise
//!   `CKM_BIP32_CHILD_KEY_DERIVE`. It returns
//!   [`Pkcs11Error::DerivationUnsupported`] when the loaded library doesn't
//!   support BIP-32 derivation.
//! - `SoftwareTweakDev` (feature-gated behind `dev-derivation`) emits loud
//!   warnings — it derives child private keys outside the HSM and **must
//!   not** be used in production.
//! - [`MinimalHsmPolicy`] provides a defense-in-depth, HSM-resident policy
//!   with per-transaction limits, a sig-rate ceiling, and a destination
//!   whitelist.

#![warn(missing_docs)]
#![deny(unsafe_code)]
#![allow(
    // chatty on every getter/builder; not a footgun in this codebase
    clippy::must_use_candidate,
    // const-fn surface area is still evolving in stable Rust
    clippy::missing_const_for_fn,
)]

pub mod config;
pub mod derivation;
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

pub use config::{Pkcs11Config, SlotIdentifier};
#[cfg(feature = "dev-derivation")]
pub use derivation::SoftwareTweakDev;
pub use derivation::{Bip32DerivationStrategy, FixedKey, HsmNativeBip32};
pub use error::Pkcs11Error;
pub use policy::MinimalHsmPolicy;
pub use session::Pkcs11Session;
pub use signer::Pkcs11Signer;
