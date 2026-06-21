//! Vendor-abstraction layer for PKCS#11 BIP-32 derivation.
//!
//! The [`HsmBackend`] trait abstracts over vendor-specific PKCS#11 mechanism
//! IDs and attribute IDs for BIP-32 key derivation. It does **not** abstract
//! over session management, signing, or object lookup — those flow through
//! [`cryptoki`] identically for every backend.
//!
//! Each implementation talks to a real PKCS#11 library:
//!
//! - In production, the library is the vendor's HSM driver (Utimaco's
//!   `libcs_pkcs11_R3.so`, Thales's `libctsw.so`, etc.).
//! - In development and CI, the library is `libasterism_dev_hsm.so` — a shim
//!   that wraps SoftHSM 2 and implements BIP-32 derivation in software. The
//!   matching backend, `DevBackend`, lives in the separate
//!   `asterism-dev-signer` crate so it never compiles into production builds.
//!
//! Asterism's compiled code is identical in every case. The only thing that
//! varies is which mechanism IDs the backend instructs `cryptoki` to send.
//!
//! ## What this trait is for
//!
//! Vendor SDKs assign their own PKCS#11 mechanism numbers to BIP-32 master
//! and child key derivation, and their own attribute numbers for the
//! companion BIP-32 metadata (chain code, depth, parent fingerprint, child
//! index). The trait carries those constants plus a small amount of glue
//! around `Session::derive_key` and `Session::get_attributes`. Everything
//! else — session open, login, key lookup, ECDSA signing, session close —
//! is straight cryptoki.
//!
//! ## Default method bodies
//!
//! `derive_master_key`, `derive_child_key`, `read_xpub`, and
//! `master_fingerprint` are provided as **default trait method
//! implementations** that use the vendor accessors
//! ([`HsmBackend::master_derive_mechanism`], etc.) plus an assumed common
//! mechanism-parameter convention:
//!
//! - **Master derivation**: the seed is passed as the entire `pParameter`
//!   blob (no length prefix, no header). The new key inherits the caller's
//!   template attributes plus `CKK_EC` over secp256k1.
//! - **Child derivation**: the parent key handle is the base, and the
//!   mechanism parameter is a 4-byte little-endian `u32` carrying the child
//!   index in BIP-32 form (high bit set means hardened).
//!
//! Vendors whose mechanism parameter struct layout diverges from this
//! convention should override the relevant methods.

use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

use crate::key_ops::SECP256K1_OID_DER;

#[cfg(feature = "thales")]
pub mod thales;
#[cfg(feature = "utimaco")]
pub mod utimaco;

#[cfg(feature = "thales")]
pub use thales::ThalesBackend;
#[cfg(feature = "utimaco")]
pub use utimaco::UtimacoBackend;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// The result of a successful master-key derivation.
#[derive(Debug, Clone)]
pub struct MasterKeyHandle {
    /// Handle to the master private key in the HSM.
    pub key_handle: ObjectHandle,
    /// XPUB at the master level, read back via [`HsmBackend::read_xpub`]
    /// after derivation.
    pub xpub: Xpub,
    /// Master fingerprint (HASH160 of the master pubkey, first 4 bytes).
    pub fingerprint: Fingerprint,
}

/// All errors produced by an [`HsmBackend`] implementation.
#[derive(Debug, thiserror::Error)]
pub enum HsmBackendError {
    /// Underlying cryptoki / PKCS#11 error.
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),

    /// BIP-32 derivation failure (invalid path segment, malformed seed, etc.).
    #[error("BIP-32 derivation error: {0}")]
    Derivation(String),

    /// A key with the requested label was not found on the token.
    #[error("key not found: {label}")]
    KeyNotFound {
        /// The label that was searched for.
        label: String,
    },

    /// Vendor BIP-32 metadata (chain code, depth, fingerprint, index) was
    /// missing or malformed when read back from the HSM.
    #[error("BIP-32 metadata error: {0}")]
    MetadataError(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Maps vendor-specific PKCS#11 mechanism IDs and attribute IDs for BIP-32
/// key derivation.
///
/// Each implementation knows which mechanism to pass to `C_DeriveKey` and
/// which vendor attributes to read from `C_GetAttributeValue` for a specific
/// HSM backend. The actual PKCS#11 calls go through [`cryptoki`] — the
/// trait just supplies the constants and shapes the parameter buffers.
///
/// Implementations must be `Send + Sync` for use in async contexts.
pub trait HsmBackend: Send + Sync + std::fmt::Debug {
    // ------------------------------------------------------------------
    // Vendor constants — every implementation must supply these.
    // ------------------------------------------------------------------

    /// PKCS#11 mechanism type for master-key derivation.
    fn master_derive_mechanism(&self) -> MechanismType;

    /// PKCS#11 mechanism type for child-key derivation.
    fn child_derive_mechanism(&self) -> MechanismType;

    /// Vendor-defined attribute type carrying the BIP-32 chain code.
    fn chain_code_attribute(&self) -> AttributeType;

    /// Vendor-defined attribute type carrying the BIP-32 depth.
    fn depth_attribute(&self) -> AttributeType;

    /// Vendor-defined attribute type carrying the parent fingerprint.
    fn parent_fingerprint_attribute(&self) -> AttributeType;

    /// Vendor-defined attribute type carrying the child index.
    fn child_index_attribute(&self) -> AttributeType;

    /// Backend identity for logging and diagnostics (e.g. `"utimaco"`,
    /// `"thales"`, `"dev"`).
    fn backend_name(&self) -> &str;

    // ------------------------------------------------------------------
    // Default operations — vendors override only when the mechanism
    // parameter struct layout diverges from the common convention.
    // ------------------------------------------------------------------

    /// Derive a BIP-32 master key from `seed` inside the HSM.
    ///
    /// Calls `C_DeriveKey` via [`Session::derive_key`] with the vendor's
    /// master-derivation mechanism. The seed must be exactly 64 bytes
    /// (the standard BIP-39 seed length); shorter or longer seeds should
    /// be normalized to 64 bytes by the caller (e.g. via PBKDF2-HMAC-SHA512
    /// per BIP-39).
    ///
    /// The seed is passed both as the mechanism's `pParameter` (for vendors
    /// like Thales / our dev shim that consume it there) and as the
    /// `CKA_VALUE` of a session-only `CKO_SECRET_KEY` base key (for
    /// vendors like Utimaco that consume it through the base-key handle).
    /// The temporary base key is destroyed after derivation.
    ///
    /// # Errors
    ///
    /// Returns [`HsmBackendError::Derivation`] if `seed.len() != 64`,
    /// [`HsmBackendError::Pkcs11`] if the underlying token rejects the
    /// request.
    fn derive_master_key(
        &self,
        session: &Session,
        seed: &[u8],
        label: &str,
    ) -> Result<MasterKeyHandle, HsmBackendError> {
        if seed.len() != 64 {
            return Err(HsmBackendError::Derivation(format!(
                "BIP-32 master seed must be 64 bytes, got {}",
                seed.len()
            )));
        }
        let mut seed_buf = [0u8; 64];
        seed_buf.copy_from_slice(seed);

        let mech_type = self.master_derive_mechanism();
        let vendor_mech = VendorDefinedMechanism::new(mech_type, Some(&seed_buf));
        let mech = Mechanism::VendorDefined(vendor_mech);

        let template = master_key_template(label);

        // Create a session-only CKO_SECRET_KEY holding the seed. This is
        // the cryptoki-friendly way to pass a "base key" handle to
        // `C_DeriveKey` — vendors that consume the seed via the mechanism
        // parameter can ignore it; vendors that consume it via the base
        // key (Utimaco-style) read CKA_VALUE.
        let seed_template = seed_secret_template(seed);
        let base_key = session.create_object(&seed_template)?;

        let result = session.derive_key(&mech, base_key, &template);

        // Best-effort cleanup: destroy the temp seed object. Errors here
        // are non-fatal — the token reaps it on session close.
        let _ = session.destroy_object(base_key);

        let key_handle = result?;
        let xpub = self.read_xpub(session, key_handle)?;
        let fingerprint = self.master_fingerprint(session, key_handle)?;
        Ok(MasterKeyHandle {
            key_handle,
            xpub,
            fingerprint,
        })
    }

    /// Derive a child key at a single BIP-32 path segment.
    ///
    /// Default convention: the mechanism parameter is a 4-byte little-endian
    /// `u32` carrying the child index in BIP-32 form (high bit set means
    /// hardened).
    ///
    /// # Errors
    ///
    /// Returns [`HsmBackendError::Pkcs11`] if the underlying token rejects
    /// the derivation request.
    fn derive_child_key(
        &self,
        session: &Session,
        parent_handle: ObjectHandle,
        child: ChildNumber,
    ) -> Result<ObjectHandle, HsmBackendError> {
        let index_word: u32 = match child {
            ChildNumber::Normal { index } => index,
            ChildNumber::Hardened { index } => index | 0x8000_0000,
        };
        let index_bytes: [u8; 4] = index_word.to_le_bytes();
        let mech_type = self.child_derive_mechanism();
        let vendor_mech = VendorDefinedMechanism::new(mech_type, Some(&index_bytes));
        let mech = Mechanism::VendorDefined(vendor_mech);

        let template = child_key_template();

        Ok(session.derive_key(&mech, parent_handle, &template)?)
    }

    /// Derive a key at a full BIP-32 path from a master key by iterating
    /// over the path segments.
    ///
    /// Vendors that natively support full-path derivation in a single
    /// `C_DeriveKey` call may override this.
    ///
    /// # Errors
    ///
    /// Returns [`HsmBackendError::Pkcs11`] if any intermediate child
    /// derivation rejects.
    fn derive_path(
        &self,
        session: &Session,
        master_handle: ObjectHandle,
        path: &DerivationPath,
    ) -> Result<ObjectHandle, HsmBackendError> {
        let mut current = master_handle;
        for child in path {
            current = self.derive_child_key(session, current, *child)?;
        }
        Ok(current)
    }

    /// Read the extended public key from `key_handle`.
    ///
    /// Reads `CKA_EC_POINT` plus the vendor-specific BIP-32 attributes
    /// (chain code, depth, parent fingerprint, child index) and assembles
    /// a [`bitcoin::bip32::Xpub`].
    ///
    /// # Errors
    ///
    /// Returns [`HsmBackendError::MetadataError`] if any required attribute
    /// is missing or malformed, or [`HsmBackendError::Pkcs11`] for token
    /// failures.
    fn read_xpub(
        &self,
        session: &Session,
        key_handle: ObjectHandle,
    ) -> Result<Xpub, HsmBackendError> {
        let attrs = session.get_attributes(
            key_handle,
            &[
                AttributeType::EcPoint,
                self.chain_code_attribute(),
                self.depth_attribute(),
                self.parent_fingerprint_attribute(),
                self.child_index_attribute(),
            ],
        )?;

        let mut ec_point: Option<Vec<u8>> = None;
        let mut chain_code: Option<Vec<u8>> = None;
        let mut depth: Option<Vec<u8>> = None;
        let mut parent_fp: Option<Vec<u8>> = None;
        let mut child_idx: Option<Vec<u8>> = None;

        for a in attrs {
            match a {
                Attribute::EcPoint(v) => ec_point = Some(v),
                Attribute::VendorDefined((t, v)) => {
                    if t == self.chain_code_attribute() {
                        chain_code = Some(v);
                    } else if t == self.depth_attribute() {
                        depth = Some(v);
                    } else if t == self.parent_fingerprint_attribute() {
                        parent_fp = Some(v);
                    } else if t == self.child_index_attribute() {
                        child_idx = Some(v);
                    }
                }
                _ => {}
            }
        }

        let ec_point = ec_point
            .ok_or_else(|| HsmBackendError::MetadataError("missing CKA_EC_POINT".into()))?;
        let chain_code = chain_code
            .ok_or_else(|| HsmBackendError::MetadataError("missing chain code".into()))?;
        let depth = depth.ok_or_else(|| HsmBackendError::MetadataError("missing depth".into()))?;
        let parent_fp = parent_fp
            .ok_or_else(|| HsmBackendError::MetadataError("missing parent fingerprint".into()))?;
        let child_idx = child_idx
            .ok_or_else(|| HsmBackendError::MetadataError("missing child index".into()))?;

        let pubkey = parse_ec_point(&ec_point)?;
        let chain_code: [u8; 32] = chain_code
            .as_slice()
            .try_into()
            .map_err(|_| HsmBackendError::MetadataError("chain code != 32 bytes".into()))?;
        let depth_byte = *depth
            .first()
            .ok_or_else(|| HsmBackendError::MetadataError("empty depth".into()))?;
        let parent_fp_arr: [u8; 4] = parent_fp
            .as_slice()
            .try_into()
            .map_err(|_| HsmBackendError::MetadataError("parent fingerprint != 4 bytes".into()))?;
        let child_idx_arr: [u8; 4] = child_idx
            .as_slice()
            .try_into()
            .map_err(|_| HsmBackendError::MetadataError("child index != 4 bytes".into()))?;
        let child_idx_word = u32::from_le_bytes(child_idx_arr);
        let child_number = if child_idx_word & 0x8000_0000 != 0 {
            ChildNumber::Hardened {
                index: child_idx_word & 0x7FFF_FFFF,
            }
        } else {
            ChildNumber::Normal {
                index: child_idx_word,
            }
        };

        let network = if depth_byte == 0 {
            bitcoin::NetworkKind::Main
        } else {
            // BIP-32 doesn't bind network to depth. We default to mainnet
            // serialization here; consumers are free to re-serialize for
            // testnet output.
            bitcoin::NetworkKind::Main
        };

        Ok(Xpub {
            network,
            depth: depth_byte,
            parent_fingerprint: Fingerprint::from(parent_fp_arr),
            child_number,
            public_key: pubkey,
            chain_code: ChainCode::from(chain_code),
        })
    }

    /// Read the master fingerprint from a key handle.
    ///
    /// Default implementation reads `CKA_EC_POINT`, parses the secp256k1
    /// public key, and returns HASH160 of its compressed serialization,
    /// truncated to 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`HsmBackendError::Pkcs11`] for token failures or
    /// [`HsmBackendError::MetadataError`] if the EC point is missing or
    /// malformed.
    fn master_fingerprint(
        &self,
        session: &Session,
        key_handle: ObjectHandle,
    ) -> Result<Fingerprint, HsmBackendError> {
        let attrs = session.get_attributes(key_handle, &[AttributeType::EcPoint])?;
        let ec_point = attrs
            .into_iter()
            .find_map(|a| match a {
                Attribute::EcPoint(v) => Some(v),
                _ => None,
            })
            .ok_or_else(|| HsmBackendError::MetadataError("missing CKA_EC_POINT".into()))?;
        let pubkey = parse_ec_point(&ec_point)?;
        let serialized = pubkey.serialize();
        let h160 = bitcoin::hashes::hash160::Hash::hash(&serialized);
        let bytes = h160.to_byte_array();
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&bytes[..4]);
        Ok(Fingerprint::from(fp))
    }
}

// ---------------------------------------------------------------------------
// Default key-template helpers
// ---------------------------------------------------------------------------

/// Standard `CKO_PRIVATE_KEY` template for a freshly-derived BIP-32 master
/// key. Vendors that need extra attributes can build their own template and
/// override [`HsmBackend::derive_master_key`].
fn master_key_template(label: &str) -> Vec<Attribute> {
    let priv_label = format!("{label}/priv");
    vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Derive(true),
        Attribute::Label(priv_label.into_bytes()),
        Attribute::EcParams(SECP256K1_OID_DER.to_vec()),
    ]
}

/// Standard `CKO_PRIVATE_KEY` template for a derived child key. Children
/// are session-only by default; the federation derivation path is
/// re-derived from the master each time a session opens.
fn child_key_template() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Derive(true),
        Attribute::EcParams(SECP256K1_OID_DER.to_vec()),
    ]
}

/// Session-only `CKO_SECRET_KEY` template for the temporary base key that
/// carries the seed bytes through `C_DeriveKey`.
fn seed_secret_template(seed: &[u8]) -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(true),
        Attribute::Value(seed.to_vec()),
    ]
}

/// Parse the contents of `CKA_EC_POINT` (which may be raw or DER OCTET
/// STRING-wrapped) into a secp256k1 public key.
fn parse_ec_point(input: &[u8]) -> Result<PublicKey, HsmBackendError> {
    let bytes = crate::key_ops::der_decode_octet_string_lenient(input)
        .map_err(|e| HsmBackendError::MetadataError(format!("EC point: {e}")))?;
    PublicKey::from_slice(&bytes)
        .map_err(|e| HsmBackendError::MetadataError(format!("invalid secp256k1 point: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny stub backend used to verify the trait's default-method
    /// implementations compile cleanly and can be used through a trait
    /// object. The mechanism numbers are arbitrary but >= CKM_VENDOR_DEFINED.
    #[derive(Debug)]
    struct StubBackend;

    impl HsmBackend for StubBackend {
        fn master_derive_mechanism(&self) -> MechanismType {
            MechanismType::new_vendor_defined(0x8000_0001).unwrap()
        }
        fn child_derive_mechanism(&self) -> MechanismType {
            MechanismType::new_vendor_defined(0x8000_0002).unwrap()
        }
        fn chain_code_attribute(&self) -> AttributeType {
            AttributeType::VendorDefined(0x8000_0101)
        }
        fn depth_attribute(&self) -> AttributeType {
            AttributeType::VendorDefined(0x8000_0102)
        }
        fn parent_fingerprint_attribute(&self) -> AttributeType {
            AttributeType::VendorDefined(0x8000_0103)
        }
        fn child_index_attribute(&self) -> AttributeType {
            AttributeType::VendorDefined(0x8000_0104)
        }
        fn backend_name(&self) -> &str {
            "stub"
        }
    }

    #[test]
    fn trait_object_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn HsmBackend>>();
    }

    #[test]
    fn stub_constants_round_trip() {
        let s = StubBackend;
        assert_eq!(s.backend_name(), "stub");
        // Ensure the vendor-defined accessors don't panic.
        let _ = s.master_derive_mechanism();
        let _ = s.child_derive_mechanism();
        let _ = s.chain_code_attribute();
    }
}
