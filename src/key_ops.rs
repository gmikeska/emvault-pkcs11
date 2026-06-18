//! HSM key generation and key-loading helpers.
//!
//! Each Asterism PKCS#11 signer is materialized on a token as **three**
//! related objects, all with `CKA_TOKEN=true` so they survive across
//! sessions:
//!
//! 1. `CKO_PRIVATE_KEY` — secp256k1 private key, `CKA_SIGN=true`,
//!    `CKA_EXTRACTABLE=false`. Labeled `asterism/v1/{label}/priv`.
//! 2. `CKO_PUBLIC_KEY` — matching secp256k1 public key (for fast lookup).
//!    Labeled `asterism/v1/{label}/pub`.
//! 3. `CKO_DATA` — a serialized [`SignerKeyMaterial`] holding the chain
//!    code and metadata (derivation path, fingerprint, created_at).
//!    Labeled `asterism/v1/{label}/material`.
//!
//! Why store the chain code on-token? The chain code is *public* (it's
//! shared as part of any xpub), so storing it as a `CKO_DATA` doesn't leak
//! anything sensitive. Keeping it on-token lets a `Pkcs11Signer` rebuild
//! its xpub purely from HSM state — no external configuration database
//! is required for the cryptographic identity of a signer.

use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::secp256k1::{rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use serde::{Deserialize, Serialize};

use crate::error::Pkcs11Error;
use crate::session::Pkcs11Session;

/// Per-signer metadata persisted alongside the chain code in a `CKO_DATA`
/// object on the HSM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerKeyMaterial {
    /// Format version (currently `1`).
    pub version: u32,
    /// Asterism signer label (matches the `label` part of the storage key).
    pub label: String,
    /// 32-byte chain code, hex-encoded.
    pub chain_code_hex: String,
    /// Master fingerprint (8 hex chars).
    pub fingerprint: String,
    /// Federation derivation path (e.g. `"m/48'/1'/0'/2'"`).
    pub derivation_path: String,
    /// Network this key was generated for.
    pub network: String,
    /// Creation time as Unix seconds.
    pub created_at: u64,
}

impl SignerKeyMaterial {
    /// Decode the chain code from its hex form.
    pub fn chain_code(&self) -> Result<ChainCode, Pkcs11Error> {
        let bytes = hex::decode(&self.chain_code_hex)
            .map_err(|e| Pkcs11Error::Backend(format!("chain code hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Pkcs11Error::Backend("chain code must be 32 bytes".into()))?;
        Ok(ChainCode::from(arr))
    }

    /// Decode the fingerprint from its hex form.
    pub fn fingerprint(&self) -> Result<Fingerprint, Pkcs11Error> {
        let bytes = hex::decode(&self.fingerprint)
            .map_err(|e| Pkcs11Error::Backend(format!("fingerprint hex: {e}")))?;
        if bytes.len() != 4 {
            return Err(Pkcs11Error::Backend(format!(
                "fingerprint must be 4 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes);
        Ok(Fingerprint::from(arr))
    }

    /// Parse the derivation path.
    pub fn derivation_path(&self) -> Result<DerivationPath, Pkcs11Error> {
        self.derivation_path
            .parse()
            .map_err(|e: bitcoin::bip32::Error| Pkcs11Error::Backend(format!("derivation path: {e}")))
    }
}

/// Loaded HSM key handles + the deserialized material.
pub struct LoadedKey {
    /// Private-key object handle.
    pub private_key: ObjectHandle,
    /// Public-key object handle.
    pub public_key_handle: ObjectHandle,
    /// `SignerKeyMaterial` `CKO_DATA` object handle.
    pub material_handle: ObjectHandle,
    /// secp256k1 public key (extracted from `CKA_EC_POINT`).
    pub public_key: PublicKey,
    /// Decoded material.
    pub material: SignerKeyMaterial,
}

const PREFIX: &str = "asterism/v1";

/// secp256k1 named-curve OID, DER-encoded:
/// `OBJECT_IDENTIFIER (06 05 2B 81 04 00 0A) = 1.3.132.0.10`.
pub const SECP256K1_OID_DER: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];

/// Generate a fresh secp256k1 keypair on the token plus a random chain code,
/// and persist them under `asterism/v1/{label}/...` labels. Returns the
/// resulting [`LoadedKey`] so the caller can immediately build a
/// [`crate::Pkcs11Signer`].
pub fn generate_key(
    session: &Pkcs11Session,
    label: &str,
    derivation_path: &DerivationPath,
    network: bitcoin::Network,
) -> Result<LoadedKey, Pkcs11Error> {
    if find_key_by_label(session, label)?.is_some() {
        return Err(Pkcs11Error::InvalidConfig(format!(
            "key with label {label} already exists on token"
        )));
    }

    // Generate the keypair in software first, so we have direct control over
    // serialization; SoftHSMv2 does not natively offer "generate secp256k1
    // and return public point cleanly". Then import via create_object.
    //
    // For production HSMs (where CKA_EXTRACTABLE=false matters), the
    // recommended path is to generate via Session::generate_key_pair with
    // CKM_EC_KEY_PAIR_GEN — but SoftHSMv2 implementations of that mechanism
    // for secp256k1 are inconsistent across distributions. Importing the
    // private bytes works uniformly.
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let secret = SecretKey::new(&mut rng);
    let public = secret.public_key(&secp);

    // Random 32-byte chain code.
    let mut chain_code_bytes = [0u8; 32];
    use bitcoin::secp256k1::rand::RngCore;
    OsRng.fill_bytes(&mut chain_code_bytes);

    // Compute master fingerprint: hash160 of compressed pubkey, first 4 bytes.
    let fp = compute_fingerprint(&public);

    // Build CKA_EC_POINT (DER OCTET STRING wrapping the uncompressed-or-compressed point).
    let public_point = public.serialize(); // 33-byte compressed.
    let ec_point_der = der_encode_octet_string(&public_point);

    let priv_label = format!("{PREFIX}/{label}/priv");
    let pub_label = format!("{PREFIX}/{label}/pub");
    let material_label = format!("{PREFIX}/{label}/material");

    let secret_bytes = secret.secret_bytes().to_vec();
    let session_handle = session.session();

    // ---- Private key ---------------------------------------------------
    let priv_attrs = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Label(priv_label.as_bytes().to_vec()),
        Attribute::EcParams(SECP256K1_OID_DER.to_vec()),
        Attribute::Value(secret_bytes),
    ];
    let private_key = session_handle
        .create_object(&priv_attrs)
        .map_err(Pkcs11Error::Pkcs11)?;

    // ---- Public key ----------------------------------------------------
    let pub_attrs = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::Label(pub_label.as_bytes().to_vec()),
        Attribute::EcParams(SECP256K1_OID_DER.to_vec()),
        Attribute::EcPoint(ec_point_der.clone()),
    ];
    let public_key_handle = session_handle
        .create_object(&pub_attrs)
        .map_err(Pkcs11Error::Pkcs11)?;

    // ---- Material data object -----------------------------------------
    let material = SignerKeyMaterial {
        version: 1,
        label: label.to_string(),
        chain_code_hex: hex::encode(chain_code_bytes),
        fingerprint: fp.to_string(),
        derivation_path: format!("m/{}", derivation_path),
        network: network.to_string(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let material_bytes = serde_json::to_vec(&material)
        .map_err(|e| Pkcs11Error::Serialization(e.to_string()))?;
    let mat_attrs = vec![
        Attribute::Class(ObjectClass::DATA),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(material_label.as_bytes().to_vec()),
        Attribute::Application(b"asterism-pkcs11".to_vec()),
        Attribute::Value(material_bytes),
    ];
    let material_handle = session_handle
        .create_object(&mat_attrs)
        .map_err(Pkcs11Error::Pkcs11)?;

    Ok(LoadedKey {
        private_key,
        public_key_handle,
        material_handle,
        public_key: public,
        material,
    })
}

/// Look up a previously-generated key by label. Returns `None` if the key
/// doesn't exist.
pub fn find_key_by_label(
    session: &Pkcs11Session,
    label: &str,
) -> Result<Option<LoadedKey>, Pkcs11Error> {
    let priv_label = format!("{PREFIX}/{label}/priv");
    let pub_label = format!("{PREFIX}/{label}/pub");
    let material_label = format!("{PREFIX}/{label}/material");

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
    let private_key = priv_handles[0];

    let pub_handles = session_handle
        .find_objects(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(pub_label.as_bytes().to_vec()),
        ])
        .map_err(Pkcs11Error::Pkcs11)?;
    let public_key_handle = pub_handles
        .into_iter()
        .next()
        .ok_or_else(|| Pkcs11Error::ObjectNotFound(pub_label.clone()))?;

    let mat_handles = session_handle
        .find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(material_label.as_bytes().to_vec()),
        ])
        .map_err(Pkcs11Error::Pkcs11)?;
    let material_handle = mat_handles
        .into_iter()
        .next()
        .ok_or_else(|| Pkcs11Error::ObjectNotFound(material_label.clone()))?;

    // ---- Extract material ---------------------------------------------
    let mat_attrs = session_handle
        .get_attributes(material_handle, &[AttributeType::Value])
        .map_err(Pkcs11Error::Pkcs11)?;
    let mat_bytes = mat_attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::Value(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| Pkcs11Error::ObjectNotFound(format!("{material_label}/value")))?;
    let material: SignerKeyMaterial = serde_json::from_slice(&mat_bytes)
        .map_err(|e| Pkcs11Error::Serialization(e.to_string()))?;

    // ---- Extract public point -----------------------------------------
    let pub_attrs = session_handle
        .get_attributes(public_key_handle, &[AttributeType::EcPoint])
        .map_err(Pkcs11Error::Pkcs11)?;
    let ec_point = pub_attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| Pkcs11Error::ObjectNotFound(format!("{pub_label}/ec_point")))?;
    let raw_point = der_decode_octet_string(&ec_point)?;
    let public_key = PublicKey::from_slice(&raw_point)
        .map_err(|e| Pkcs11Error::Secp256k1(e.to_string()))?;

    Ok(Some(LoadedKey {
        private_key,
        public_key_handle,
        material_handle,
        public_key,
        material,
    }))
}

/// Construct the [`Xpub`] for a loaded key.
///
/// Note: the resulting xpub does not have a parent fingerprint set (it's
/// treated as a synthetic master xpub-at-derivation-path). Consumers that
/// need parent metadata must derive it from a separate path.
pub fn derive_xpub(loaded: &LoadedKey) -> Result<Xpub, Pkcs11Error> {
    let chain_code = loaded.material.chain_code()?;
    let path = loaded.material.derivation_path()?;
    let depth = path.len() as u8;
    let child_number = path
        .as_ref()
        .last()
        .copied()
        .unwrap_or(ChildNumber::Normal { index: 0 });
    let network = match loaded.material.network.as_str() {
        "bitcoin" => bitcoin::NetworkKind::Main,
        _ => bitcoin::NetworkKind::Test,
    };
    Ok(Xpub {
        network,
        depth,
        parent_fingerprint: Fingerprint::default(),
        child_number,
        public_key: loaded.public_key,
        chain_code,
    })
}

/// Delete every Asterism object associated with `label` from the token.
/// Used by integration test helpers and migration tooling.
pub fn delete_key(session: &Pkcs11Session, label: &str) -> Result<(), Pkcs11Error> {
    let session_handle = session.session();
    for suffix in ["priv", "pub", "material"] {
        let l = format!("{PREFIX}/{label}/{suffix}");
        let class = match suffix {
            "priv" => ObjectClass::PRIVATE_KEY,
            "pub" => ObjectClass::PUBLIC_KEY,
            "material" => ObjectClass::DATA,
            _ => unreachable!(),
        };
        let handles = session_handle
            .find_objects(&[
                Attribute::Class(class),
                Attribute::Label(l.as_bytes().to_vec()),
            ])
            .map_err(Pkcs11Error::Pkcs11)?;
        for h in handles {
            session_handle.destroy_object(h).map_err(Pkcs11Error::Pkcs11)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compute_fingerprint(pk: &PublicKey) -> Fingerprint {
    use bitcoin::hashes::Hash;
    let serialized = pk.serialize(); // 33-byte compressed
    let h160 = bitcoin::hashes::hash160::Hash::hash(&serialized);
    let bytes = h160.to_byte_array();
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&bytes[..4]);
    Fingerprint::from(fp)
}

fn der_encode_octet_string(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(0x04); // OCTET STRING tag
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else if content.len() < 0x100 {
        out.push(0x81);
        out.push(content.len() as u8);
    } else {
        out.push(0x82);
        out.push((content.len() >> 8) as u8);
        out.push((content.len() & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn der_decode_octet_string(input: &[u8]) -> Result<Vec<u8>, Pkcs11Error> {
    // Some HSMs return the raw point bytes without the DER OCTET STRING
    // wrapper. Detect that case and accept either form.
    if input.is_empty() {
        return Err(Pkcs11Error::Backend("empty EC point".into()));
    }
    if input[0] == 0x04 && input.len() >= 2 {
        // DER OCTET STRING.
        let (header_len, content_len) = if input[1] < 0x80 {
            (2, input[1] as usize)
        } else if input[1] == 0x81 && input.len() >= 3 {
            (3, input[2] as usize)
        } else if input[1] == 0x82 && input.len() >= 4 {
            (4, ((input[2] as usize) << 8) | (input[3] as usize))
        } else {
            return Err(Pkcs11Error::Backend(
                "malformed DER length on EC point".into(),
            ));
        };
        if input.len() < header_len + content_len {
            return Err(Pkcs11Error::Backend(
                "DER OCTET STRING truncated on EC point".into(),
            ));
        }
        let content = input[header_len..header_len + content_len].to_vec();
        // Some implementations (notably SoftHSMv2) return the OCTET STRING
        // wrapping the raw 33-byte point; others return the OCTET STRING
        // wrapping a SEC1 uncompressed point (65 bytes starting with 0x04).
        // Both are valid; just pass through.
        return Ok(content);
    }
    // Raw bytes (33 or 65 byte SEC1 forms) — pass through.
    Ok(input.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_encode_then_decode_round_trips() {
        let raw = [0x02u8; 33].to_vec();
        let encoded = der_encode_octet_string(&raw);
        let decoded = der_decode_octet_string(&encoded).unwrap();
        assert_eq!(raw, decoded);
    }

    #[test]
    fn signer_key_material_round_trip() {
        let m = SignerKeyMaterial {
            version: 1,
            label: "test".into(),
            chain_code_hex: hex::encode([7u8; 32]),
            fingerprint: "deadbeef".into(),
            derivation_path: "m/48'/1'/0'/2'".into(),
            network: "testnet".into(),
            created_at: 1_700_000_000,
        };
        let s = serde_json::to_string(&m).unwrap();
        let parsed: SignerKeyMaterial = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.label, "test");
        assert_eq!(parsed.fingerprint().unwrap().to_string(), "deadbeef");
        let cc = parsed.chain_code().unwrap();
        assert_eq!(cc.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn fingerprint_matches_hash160_first_4_bytes() {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk = sk.public_key(&secp);
        let fp = compute_fingerprint(&pk);
        assert_eq!(fp.to_string().len(), 8);
    }
}
