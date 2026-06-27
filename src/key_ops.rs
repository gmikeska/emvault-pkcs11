//! HSM key lookup and removal helpers.
//!
//! With the move to [`crate::backend::HsmBackend`]-driven BIP-32 derivation,
//! this module no longer owns key generation or chain-code persistence —
//! the HSM itself (real hardware, or `libemvault_dev_hsm.so` in dev) is the
//! source of truth for derived keys and their BIP-32 metadata. The vendor
//! BIP-32 attributes ([`HsmBackend::chain_code_attribute`] and friends)
//! carry the chain code; there is no longer a separate `CKO_DATA` material
//! object.
//!
//! What remains here:
//!
//! - [`find_key_by_label`] — locate a previously-derived key on the token
//!   by its label and return both handles a [`crate::Pkcs11Signer`] needs.
//! - [`delete_key`] — remove a key from the token. The dev shim cleans up
//!   its companion BIP-32 metadata automatically; production HSMs handle
//!   their own metadata via vendor attributes attached to the key object.
//!
//! [`HsmBackend::chain_code_attribute`]: crate::backend::HsmBackend::chain_code_attribute

use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};

use crate::error::Pkcs11Error;
use crate::session::Pkcs11Session;

/// EmVault label namespace prefix. Every object created by this crate
/// goes under `emvault/v1/{label}/...` so we can find them later without
/// risk of colliding with externally-managed token contents.
pub const PREFIX: &str = "emvault/v1";

/// secp256k1 named-curve OID, DER-encoded:
/// `OBJECT_IDENTIFIER (06 05 2B 81 04 00 0A) = 1.3.132.0.10`.
pub const SECP256K1_OID_DER: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];

/// Suffix for the federation-derivation private key.
pub const PRIV_SUFFIX: &str = "priv";
/// Suffix for the federation-derivation public key.
pub const PUB_SUFFIX: &str = "pub";

/// The handles a [`crate::Pkcs11Signer`] needs to operate on an existing
/// HSM key. [`HsmBackend::read_xpub`](crate::backend::HsmBackend::read_xpub)
/// reads everything else (chain code, depth, fingerprint, child index) via
/// vendor attributes.
#[derive(Debug, Clone, Copy)]
pub struct LoadedKey {
    /// Federation-derivation private key handle (used for ECDSA signing).
    pub private_key: ObjectHandle,
}

/// Build the canonical EmVault label for the federation-derivation
/// private key. Mirrors the layout the dev shim and production HSMs
/// expect.
pub fn priv_label(label: &str) -> String {
    format!("{PREFIX}/{label}/{PRIV_SUFFIX}")
}

/// Build the canonical EmVault label for the federation-derivation
/// public key.
pub fn pub_label(label: &str) -> String {
    format!("{PREFIX}/{label}/{PUB_SUFFIX}")
}

/// Look up a previously-derived key by label.
///
/// Returns `None` if no key with `label` exists on the token. EmVault
/// labels are namespaced as `emvault/v1/{label}/priv`.
///
/// # Errors
///
/// Returns [`Pkcs11Error::Pkcs11`] if the underlying `find_objects` call
/// fails, or [`Pkcs11Error::Ambiguous`] if more than one key matches.
pub fn find_key_by_label(
    session: &Pkcs11Session,
    label: &str,
) -> Result<Option<LoadedKey>, Pkcs11Error> {
    let priv_label = priv_label(label);
    let session_handle = session.session();
    let priv_handles = session_handle
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(priv_label.as_bytes().to_vec()),
        ])
        .map_err(Pkcs11Error::Pkcs11)?;
    if priv_handles.is_empty() {
        return Ok(None);
    }
    if priv_handles.len() != 1 {
        return Err(Pkcs11Error::Ambiguous {
            query: priv_label,
            count: priv_handles.len(),
        });
    }
    Ok(Some(LoadedKey {
        private_key: priv_handles[0],
    }))
}

/// Delete every EmVault object associated with `label` from the token.
///
/// Removes the federation-derivation private and public key objects under
/// `emvault/v1/{label}/{priv,pub}`. The dev shim destroys its companion
/// BIP-32 metadata automatically when the key is destroyed (per the dev
/// shim's `C_DestroyObject` interception); production HSMs carry their
/// metadata as vendor attributes on the key itself.
///
/// Used by integration test helpers and migration tooling.
///
/// # Errors
///
/// Returns [`Pkcs11Error::Pkcs11`] if the underlying token rejects any of
/// the `find_objects` / `destroy_object` calls.
pub fn delete_key(session: &Pkcs11Session, label: &str) -> Result<(), Pkcs11Error> {
    let session_handle = session.session();
    for (suffix, class) in [
        (PRIV_SUFFIX, ObjectClass::PRIVATE_KEY),
        (PUB_SUFFIX, ObjectClass::PUBLIC_KEY),
    ] {
        let l = format!("{PREFIX}/{label}/{suffix}");
        let handles = session_handle
            .find_objects(&[
                Attribute::Class(class),
                Attribute::Label(l.as_bytes().to_vec()),
            ])
            .map_err(Pkcs11Error::Pkcs11)?;
        for h in handles {
            session_handle
                .destroy_object(h)
                .map_err(Pkcs11Error::Pkcs11)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EC point DER helpers (shared with the backend layer)
// ---------------------------------------------------------------------------

/// Lenient DER OCTET STRING decoder for `CKA_EC_POINT` payloads.
///
/// PKCS#11 v2.40 wraps EC public points in a DER OCTET STRING; some
/// implementations (notably SoftHSM 2 in older builds) return the raw
/// bytes. This helper accepts either form.
///
/// # Errors
///
/// Returns an error string if the input is empty or malformed.
pub fn der_decode_octet_string_lenient(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Err("empty EC point".into());
    }
    if input[0] == 0x04 && input.len() >= 2 {
        let (header_len, content_len) = if input[1] < 0x80 {
            (2, input[1] as usize)
        } else if input[1] == 0x81 && input.len() >= 3 {
            (3, input[2] as usize)
        } else if input[1] == 0x82 && input.len() >= 4 {
            (4, ((input[2] as usize) << 8) | (input[3] as usize))
        } else {
            return Err("malformed DER length on EC point".into());
        };
        if input.len() < header_len + content_len {
            return Err("DER OCTET STRING truncated on EC point".into());
        }
        return Ok(input[header_len..header_len + content_len].to_vec());
    }
    // Raw bytes (33-byte compressed or 65-byte uncompressed SEC1 form).
    Ok(input.to_vec())
}

/// DER-encode a byte slice as an OCTET STRING. Used when a vendor expects
/// `CKA_EC_POINT` in the PKCS#11 v2.40 wrapped form.
///
/// # Panics
///
/// Panics if `content.len() >= 0x10000` (more than two-byte DER length
/// fields are not produced here); SEC1 EC points are always 33 or 65
/// bytes, so this never fires for in-tree callers.
pub fn der_encode_octet_string(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(0x04);
    if content.len() < 0x80 {
        out.push(u8::try_from(content.len()).expect("len < 0x80 fits u8"));
    } else if content.len() < 0x100 {
        out.push(0x81);
        out.push(u8::try_from(content.len()).expect("len < 0x100 fits u8"));
    } else {
        out.push(0x82);
        out.push(u8::try_from(content.len() >> 8).expect("len >> 8 < 0x100 for OCTET STRING"));
        out.push(u8::try_from(content.len() & 0xff).expect("low byte fits u8"));
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_encode_then_decode_round_trips() {
        let raw = [0x02u8; 33].to_vec();
        let encoded = der_encode_octet_string(&raw);
        let decoded = der_decode_octet_string_lenient(&encoded).unwrap();
        assert_eq!(raw, decoded);
    }

    #[test]
    fn der_decode_accepts_raw_bytes() {
        // 33-byte compressed point with 0x02 prefix gets passed through
        // unchanged. (The leading 0x02 is a valid SEC1 marker, not a DER
        // OCTET STRING tag.)
        let raw = vec![0x02u8; 33];
        let decoded = der_decode_octet_string_lenient(&raw).unwrap();
        assert_eq!(raw, decoded);
    }

    #[test]
    fn label_helpers_use_namespace() {
        assert_eq!(priv_label("foo"), "emvault/v1/foo/priv");
        assert_eq!(pub_label("foo"), "emvault/v1/foo/pub");
    }
}
