//! Configuration types for opening a PKCS#11 session and selecting a
//! BIP-32-aware HSM backend.
//!
//! [`Pkcs11Config`] carries everything `Pkcs11Signer` needs to wire up an
//! HSM-backed key:
//!
//! - **`library_path`** — which PKCS#11 shared library to load. In
//!   production this is the vendor's `.so` (e.g. `libcs_pkcs11_R3.so` for
//!   Utimaco). In development and CI it's `libasterism_dev_hsm.so` — the
//!   PKCS#11 shim that wraps SoftHSM 2 with software BIP-32 derivation.
//! - **`slot`** — which token to talk to (by label or numeric slot id).
//! - **`pin`** — user PIN, held in [`secrecy::SecretString`] so it doesn't
//!   accidentally end up in logs.
//! - **`derivation_path`** — the federation BIP-32 path the signer
//!   participates at (e.g. `m/48'/1'/0'/2'`).
//! - **`backend`** — a [`Box<dyn HsmBackend>`](crate::backend::HsmBackend)
//!   carrying the vendor-specific mechanism IDs and attribute IDs for
//!   BIP-32 derivation. The standard cryptoki path stays vendor-agnostic;
//!   only the derivation calls are routed through the backend.

use std::path::PathBuf;

use bitcoin::bip32::DerivationPath;
use secrecy::SecretString;

use crate::backend::HsmBackend;
use crate::error::Pkcs11Error;

/// Configuration for opening a PKCS#11 session.
///
/// Constructed via [`Self::builder`] or directly. The struct is `!Clone`
/// because [`Box<dyn HsmBackend>`] can't be cloned through the trait
/// object — instantiate a fresh config (cheap) instead of cloning.
pub struct Pkcs11Config {
    /// Filesystem path to the PKCS#11 shared library.
    pub library_path: PathBuf,
    /// Token selector (label or slot id).
    pub slot: SlotIdentifier,
    /// User PIN.
    pub pin: SecretString,
    /// BIP-32 derivation path for this signer's federation key.
    pub derivation_path: DerivationPath,
    /// Vendor backend carrying mechanism/attribute IDs for BIP-32
    /// derivation through this PKCS#11 library.
    pub backend: Box<dyn HsmBackend>,
}

impl std::fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("library_path", &self.library_path)
            .field("slot", &self.slot)
            .field("derivation_path", &self.derivation_path)
            .field("backend", &self.backend.backend_name())
            .finish_non_exhaustive()
    }
}

impl Pkcs11Config {
    /// Construct a config with all fields supplied directly.
    pub fn new(
        library_path: impl Into<PathBuf>,
        slot: SlotIdentifier,
        pin: impl Into<SecretString>,
        derivation_path: DerivationPath,
        backend: Box<dyn HsmBackend>,
    ) -> Self {
        Self {
            library_path: library_path.into(),
            slot,
            pin: pin.into(),
            derivation_path,
            backend,
        }
    }

    /// Read the PKCS#11 library path from the environment.
    ///
    /// Looks at `PKCS11_LIB` first (the conventional dev/prod knob), then
    /// falls back to `SOFTHSM2_LIB` for legacy SoftHSM-direct setups.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error::Env`] if neither variable is set.
    pub fn library_path_from_env() -> Result<PathBuf, Pkcs11Error> {
        let path = std::env::var("PKCS11_LIB")
            .ok()
            .or_else(|| std::env::var("SOFTHSM2_LIB").ok())
            .ok_or(Pkcs11Error::Env {
                var: "PKCS11_LIB",
                reason: "neither PKCS11_LIB nor SOFTHSM2_LIB is set".into(),
            })?;
        Ok(PathBuf::from(path))
    }
}

/// How a caller identifies a slot on the PKCS#11 module.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SlotIdentifier {
    /// Match by token label (recommended — stable across slot reordering).
    Label(String),
    /// Match by raw slot id.
    SlotId(u64),
}

impl SlotIdentifier {
    /// Convenience constructor for label-based selection.
    pub fn label(s: impl Into<String>) -> Self {
        Self::Label(s.into())
    }
    /// Convenience constructor for slot-id selection.
    pub fn slot_id(id: u64) -> Self {
        Self::SlotId(id)
    }
}

impl std::fmt::Display for SlotIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Label(l) => write!(f, "label={l}"),
            Self::SlotId(id) => write!(f, "slot_id={id}"),
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn slot_identifier_serializes_with_kind_tag() {
        let label = SlotIdentifier::label("asterism-test");
        let json = serde_json::to_string(&label).unwrap();
        assert!(json.contains("\"kind\":\"label\""), "got {json}");
        assert!(json.contains("\"asterism-test\""));
    }

    #[test]
    fn slot_identifier_round_trips() {
        let cases = [SlotIdentifier::label("foo"), SlotIdentifier::slot_id(7)];
        for c in &cases {
            let json = serde_json::to_string(c).unwrap();
            let parsed: SlotIdentifier = serde_json::from_str(&json).unwrap();
            assert_eq!(c.to_string(), parsed.to_string());
        }
    }

    #[test]
    fn library_path_from_env_reads_pkcs11_lib() {
        let prev_softhsm = std::env::var("SOFTHSM2_LIB").ok();
        let prev_pkcs11 = std::env::var("PKCS11_LIB").ok();
        // SAFETY: we restore the prior environment at end of test.
        unsafe {
            std::env::remove_var("SOFTHSM2_LIB");
            std::env::remove_var("PKCS11_LIB");
        }
        assert!(Pkcs11Config::library_path_from_env().is_err());
        unsafe {
            std::env::set_var("SOFTHSM2_LIB", "/tmp/softhsm.so");
        }
        let path = Pkcs11Config::library_path_from_env().unwrap();
        assert_eq!(path, PathBuf::from("/tmp/softhsm.so"));
        unsafe {
            std::env::set_var("PKCS11_LIB", "/tmp/pkcs11.so");
        }
        let path = Pkcs11Config::library_path_from_env().unwrap();
        assert_eq!(path, PathBuf::from("/tmp/pkcs11.so"));
        unsafe {
            std::env::remove_var("SOFTHSM2_LIB");
            std::env::remove_var("PKCS11_LIB");
        }
        if let Some(v) = prev_softhsm {
            unsafe {
                std::env::set_var("SOFTHSM2_LIB", v);
            }
        }
        if let Some(v) = prev_pkcs11 {
            unsafe {
                std::env::set_var("PKCS11_LIB", v);
            }
        }
    }
}
