//! PKCS#11 ECDSA signing helpers.
//!
//! Wraps the raw `Session::sign` call with secp256k1-aware low-S
//! normalization (BIP-146) and BIP-66 DER encoding so the resulting
//! signatures are accepted by Bitcoin nodes.

use bitcoin::secp256k1::ecdsa::Signature;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;

use crate::error::Pkcs11Error;

/// Sign a 32-byte sighash with the given private-key handle, applying
/// low-S normalization (BIP-146) so the resulting signature is canonical
/// and won't be rejected by a Bitcoin node's STRICTENC enforcement.
///
/// The PKCS#11 `CKM_ECDSA` mechanism takes pre-hashed input and returns a
/// raw `(r || s)` 64-byte signature. We re-pack via
/// `secp256k1::ecdsa::Signature::from_compact` to get a structured
/// signature, then call `normalize_s()` to enforce the low-S rule.
pub fn sign_with_low_s(
    session: &Session,
    private_key: ObjectHandle,
    sighash: &[u8; 32],
) -> Result<Signature, Pkcs11Error> {
    let raw = session
        .sign(&Mechanism::Ecdsa, private_key, sighash)
        .map_err(Pkcs11Error::Pkcs11)?;
    if raw.len() != 64 {
        return Err(Pkcs11Error::Backend(format!(
            "PKCS#11 ECDSA returned {} bytes, expected 64 (r || s)",
            raw.len()
        )));
    }
    let mut sig =
        Signature::from_compact(&raw).map_err(|e| Pkcs11Error::Secp256k1(e.to_string()))?;
    sig.normalize_s();
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Sanity check: ensure a software-generated signature passes
    /// `verify` after normalization. (We can't unit-test the actual
    /// PKCS#11 path without an HSM session.)
    #[test]
    fn normalized_signature_verifies() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = sk.public_key(&secp);
        let msg = Message::from_digest([3u8; 32]);
        let mut sig = secp.sign_ecdsa(&msg, &sk);
        sig.normalize_s();
        secp.verify_ecdsa(&msg, &sig, &pk).unwrap();
    }
}
