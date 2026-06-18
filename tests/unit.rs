//! Stand-alone unit tests that don't require an HSM session.
//!
//! Integration tests against SoftHSMv2 live in `integration.rs` and are
//! gated behind the `integration` feature.

use asterism_core::SignerError;
use asterism_pkcs11::{
    config::{Pkcs11Config, SlotIdentifier},
    error::Pkcs11Error,
};

#[test]
fn pkcs11_error_policy_violation_maps_to_signer_policy_violation() {
    let e = Pkcs11Error::PolicyViolation("rule X failed".into());
    let s: SignerError = e.into();
    match s {
        SignerError::PolicyViolation { rule, .. } => {
            assert_eq!(rule, "rule X failed");
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn pkcs11_error_derivation_unsupported_maps_to_signing_failed() {
    let e = Pkcs11Error::DerivationUnsupported {
        strategy: "HsmNativeBip32",
        reason: "no mechanism".into(),
    };
    let s: SignerError = e.into();
    match s {
        SignerError::SigningFailed { reason, .. } => {
            assert!(reason.contains("HsmNativeBip32"));
            assert!(reason.contains("no mechanism"));
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn pkcs11_error_other_maps_to_backend() {
    let e = Pkcs11Error::SlotNotFound("label=foo".into());
    let s: SignerError = e.into();
    assert!(matches!(s, SignerError::Backend(_)));
}

#[test]
fn slot_identifier_display() {
    assert_eq!(SlotIdentifier::label("foo").to_string(), "label=foo");
    assert_eq!(SlotIdentifier::slot_id(7).to_string(), "slot_id=7");
}

#[test]
fn pkcs11_config_new_is_path_buf_compatible() {
    let cfg = Pkcs11Config::new("/usr/lib/softhsm/libsofthsm2.so");
    assert_eq!(
        cfg.library_path,
        std::path::PathBuf::from("/usr/lib/softhsm/libsofthsm2.so")
    );
}
