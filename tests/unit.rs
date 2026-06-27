//! Stand-alone unit tests that don't require an HSM session.
//!
//! Integration tests against a live PKCS#11 token live in `integration.rs`
//! and are gated behind the `integration` feature.

use emvault_core::SignerError;
use emvault_pkcs11::{HsmBackendError, config::SlotIdentifier, error::Pkcs11Error};

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
fn hsm_backend_error_derivation_maps_to_signing_failed() {
    let e = Pkcs11Error::HsmBackend(HsmBackendError::Derivation("seed length wrong".into()));
    let s: SignerError = e.into();
    match s {
        SignerError::SigningFailed { reason, .. } => {
            assert!(reason.contains("seed length wrong"), "got: {reason}");
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn hsm_backend_error_key_not_found_maps_to_backend() {
    let e = Pkcs11Error::HsmBackend(HsmBackendError::KeyNotFound {
        label: "fed-1".into(),
    });
    let s: SignerError = e.into();
    match s {
        SignerError::Backend(msg) => {
            assert!(msg.contains("fed-1"), "got: {msg}");
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
