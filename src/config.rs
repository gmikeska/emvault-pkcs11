//! Configuration types: which PKCS#11 module to load, which slot to use,
//! and how to resolve a slot.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Pkcs11Error;

/// Configuration for opening a PKCS#11 session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pkcs11Config {
    /// Filesystem path to the PKCS#11 shared library
    /// (e.g. `/usr/lib/softhsm/libsofthsm2.so`).
    pub library_path: PathBuf,
}

impl Pkcs11Config {
    /// Construct a config with an explicit library path.
    pub fn new(library_path: impl Into<PathBuf>) -> Self {
        Self {
            library_path: library_path.into(),
        }
    }

    /// Build a `Pkcs11Config` from the `SOFTHSM2_LIB` environment variable
    /// (the standard variable used in the project's `.env`). Falls back to
    /// `PKCS11_LIB` for non-SoftHSM deployments.
    pub fn from_env() -> Result<Self, Pkcs11Error> {
        let path = std::env::var("SOFTHSM2_LIB")
            .ok()
            .or_else(|| std::env::var("PKCS11_LIB").ok())
            .ok_or(Pkcs11Error::Env {
                var: "SOFTHSM2_LIB",
                reason: "neither SOFTHSM2_LIB nor PKCS11_LIB is set".into(),
            })?;
        Ok(Self::new(path))
    }
}

/// How a caller identifies a slot on the PKCS#11 module.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SlotIdentifier {
    /// Match by token label (recommended — stable across slot reordering).
    Label(String),
    /// Match by raw slot ID.
    SlotId(u64),
}

impl SlotIdentifier {
    /// Convenience constructor for label-based selection.
    pub fn label(s: impl Into<String>) -> Self {
        SlotIdentifier::Label(s.into())
    }
    /// Convenience constructor for slot-id selection.
    pub fn slot_id(id: u64) -> Self {
        SlotIdentifier::SlotId(id)
    }
}

impl std::fmt::Display for SlotIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotIdentifier::Label(l) => write!(f, "label={l}"),
            SlotIdentifier::SlotId(id) => write!(f, "slot_id={id}"),
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
        let cases = [
            SlotIdentifier::label("foo"),
            SlotIdentifier::slot_id(7),
        ];
        for c in &cases {
            let json = serde_json::to_string(c).unwrap();
            let parsed: SlotIdentifier = serde_json::from_str(&json).unwrap();
            assert_eq!(c.to_string(), parsed.to_string());
        }
    }

    #[test]
    fn config_from_env_reads_softhsm_var() {
        // Don't pollute global env in tests.
        // SAFETY: tests for env-reading run serially via a separate path.
        let prev_softhsm = std::env::var("SOFTHSM2_LIB").ok();
        let prev_pkcs11 = std::env::var("PKCS11_LIB").ok();
        unsafe {
            std::env::remove_var("SOFTHSM2_LIB");
            std::env::remove_var("PKCS11_LIB");
        }
        // Empty environment → error.
        assert!(Pkcs11Config::from_env().is_err());
        unsafe { std::env::set_var("PKCS11_LIB", "/tmp/fake.so"); }
        let cfg = Pkcs11Config::from_env().unwrap();
        assert_eq!(cfg.library_path, std::path::PathBuf::from("/tmp/fake.so"));
        unsafe { std::env::remove_var("PKCS11_LIB"); }
        unsafe {
            std::env::set_var("SOFTHSM2_LIB", "/tmp/softhsm.so");
        }
        let cfg = Pkcs11Config::from_env().unwrap();
        assert_eq!(cfg.library_path, std::path::PathBuf::from("/tmp/softhsm.so"));
        // Restore prior env.
        unsafe { std::env::remove_var("SOFTHSM2_LIB"); }
        if let Some(v) = prev_softhsm { unsafe { std::env::set_var("SOFTHSM2_LIB", v); } }
        if let Some(v) = prev_pkcs11 { unsafe { std::env::set_var("PKCS11_LIB", v); } }
    }
}
