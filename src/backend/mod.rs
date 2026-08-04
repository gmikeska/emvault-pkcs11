//! Vendor-abstraction layer for PKCS#11 BIP-32 derivation.
//!
//! Two traits split the concern cleanly:
//!
//! - [`HsmBackend`] is the **signer-facing contract** — the exact set of
//!   operations [`Pkcs11Signer`](crate::signer::Pkcs11Signer) invokes:
//!   `derive_master_key`, `derive_path`, `read_xpub`, `master_fingerprint`,
//!   plus a `backend_name`. Session management, signing, and object lookup are
//!   **not** abstracted — they flow through [`cryptoki`] identically for every
//!   backend.
//! - [`AttributeDerivation`] is the **standard attribute-based recipe** — the
//!   vendor mechanism IDs and attribute IDs for the common cryptoki derivation
//!   convention. A backend that fits that convention implements *only* this
//!   trait and gets a full `HsmBackend` for free through the blanket impl
//!   below.
//!
//! Each implementation talks to a real PKCS#11 library:
//!
//! - In production, the library is the vendor's HSM driver. Vendor-specific
//!   backends live in their own downstream crates so each deployment pulls in
//!   only the vendor SDK it actually uses.
//! - In development and CI, the library is `libemvault_dev_hsm.so` — a shim
//!   that wraps SoftHSM 2 and implements BIP-32 derivation in software. The
//!   matching backend, `DevBackend`, lives in the separate `emvault-dev-signer`
//!   crate; it implements [`AttributeDerivation`].
//!
//! ## Which trait to implement
//!
//! Vendor SDKs assign their own PKCS#11 mechanism numbers to BIP-32 master and
//! child derivation, and their own attribute numbers for the companion BIP-32
//! metadata (chain code, depth, parent fingerprint, child index).
//!
//! - If your HSM follows the common convention — `C_DeriveKey` with a vendor
//!   mechanism per level (child param = 4-byte LE `u32`, hardened = high bit),
//!   metadata exposed as vendor attributes — implement [`AttributeDerivation`]
//!   and you're done.
//! - If it diverges (e.g. Securosys derives a whole path in one
//!   `C_DeriveKeyPair` and doesn't expose the positional metadata as
//!   attributes), implement [`HsmBackend`] **directly** and skip
//!   `AttributeDerivation` entirely.

use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

use crate::key_ops::SECP256K1_OID_DER;

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
// Signer-facing contract
// ---------------------------------------------------------------------------

/// The signer-facing HSM contract: everything
/// [`Pkcs11Signer`](crate::signer::Pkcs11Signer) needs to create, reload, and
/// sign with an HSM-held BIP-32 key.
///
/// Most backends get this **for free** by implementing [`AttributeDerivation`]
/// (the blanket impl below supplies these methods from the vendor accessors).
/// Implement `HsmBackend` **directly** only when the HSM's derivation doesn't
/// fit the attribute-based convention.
///
/// Implementations must be `Send + Sync` for use in async contexts.
pub trait HsmBackend: Send + Sync + std::fmt::Debug {
    /// Backend identity for logging and diagnostics (e.g. `"dev"`, or a vendor
    /// identifier supplied by a downstream crate).
    fn backend_name(&self) -> &'static str;

    /// Derive a BIP-32 master key from `seed` inside the HSM.
    ///
    /// The seed must be exactly 64 bytes (the standard BIP-39 seed length), or
    /// empty (`&[]`) for backends that resolve the seed themselves (e.g. the
    /// dev shim's slot-keyed preloaded BIP-39 mnemonics).
    ///
    /// # Errors
    /// Returns [`HsmBackendError::Derivation`] for a malformed seed, or
    /// [`HsmBackendError::Pkcs11`] if the token rejects the request.
    fn derive_master_key(
        &self,
        session: &Session,
        seed: &[u8],
        label: &str,
    ) -> Result<MasterKeyHandle, HsmBackendError>;

    /// Derive a key at a full BIP-32 path from a master key.
    ///
    /// # Errors
    /// Returns [`HsmBackendError::Pkcs11`] if any derivation step rejects.
    fn derive_path(
        &self,
        session: &Session,
        master_handle: ObjectHandle,
        path: &DerivationPath,
    ) -> Result<ObjectHandle, HsmBackendError>;

    /// Read the extended public key from `key_handle`.
    ///
    /// # Errors
    /// Returns [`HsmBackendError::MetadataError`] if metadata is missing or
    /// malformed, or [`HsmBackendError::Pkcs11`] for token failures.
    fn read_xpub(
        &self,
        session: &Session,
        key_handle: ObjectHandle,
    ) -> Result<Xpub, HsmBackendError>;

    /// Read the master fingerprint (HASH160 of the master pubkey, first 4
    /// bytes) from a key handle.
    ///
    /// # Errors
    /// Returns [`HsmBackendError::MetadataError`] if the EC point is missing or
    /// malformed, or [`HsmBackendError::Pkcs11`] for token failures.
    fn master_fingerprint(
        &self,
        session: &Session,
        key_handle: ObjectHandle,
    ) -> Result<Fingerprint, HsmBackendError>;
}

// ---------------------------------------------------------------------------
// Standard attribute-based recipe
// ---------------------------------------------------------------------------

/// Vendor mechanism/attribute IDs for the **standard attribute-based** BIP-32
/// derivation path.
///
/// A backend that derives through the common cryptoki convention — `C_DeriveKey`
/// with a vendor mechanism per level and vendor attributes read back for the
/// BIP-32 metadata — implements this trait, and gets a full [`HsmBackend`] for
/// free via the blanket impl below.
///
/// Implementations must be `Send + Sync` for use in async contexts.
pub trait AttributeDerivation: Send + Sync + std::fmt::Debug {
    /// Backend identity for logging and diagnostics (e.g. `"dev"`).
    fn backend_name(&self) -> &'static str;

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

    /// Derive a child key at a single BIP-32 path segment.
    ///
    /// Default convention: the mechanism parameter is a 4-byte little-endian
    /// `u32` carrying the child index in BIP-32 form (high bit set means
    /// hardened). Override only if the child-derivation parameter differs.
    ///
    /// # Errors
    /// Returns [`HsmBackendError::Pkcs11`] if the token rejects the request.
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
}

/// Blanket impl: every [`AttributeDerivation`] backend is a full [`HsmBackend`]
/// via the standard attribute-based cryptoki derivation. Backends that need a
/// different derivation shape implement [`HsmBackend`] directly instead (and do
/// not implement `AttributeDerivation`).
impl<T: AttributeDerivation> HsmBackend for T {
    fn backend_name(&self) -> &'static str {
        <T as AttributeDerivation>::backend_name(self)
    }

    fn derive_master_key(
        &self,
        session: &Session,
        seed: &[u8],
        label: &str,
    ) -> Result<MasterKeyHandle, HsmBackendError> {
        if !seed.is_empty() && seed.len() != 64 {
            return Err(HsmBackendError::Derivation(format!(
                "BIP-32 master seed must be 64 bytes (or empty for backend-resolved \
                 seeds), got {}",
                seed.len()
            )));
        }
        let mut seed_buf = [0u8; 64];
        if seed.len() == 64 {
            seed_buf.copy_from_slice(seed);
        }

        let mech_type = self.master_derive_mechanism();
        let vendor_mech = VendorDefinedMechanism::new(mech_type, Some(&seed_buf));
        let mech = Mechanism::VendorDefined(vendor_mech);

        let template = master_key_template(label);

        // Create a session-only CKO_SECRET_KEY holding the seed. This is
        // the cryptoki-friendly way to pass a "base key" handle to
        // `C_DeriveKey` — vendors that consume the seed via the mechanism
        // parameter can ignore it; vendors that consume it via the base
        // key read CKA_VALUE. For empty `seed`, the value is 64 zero
        // bytes (the dev shim treats that as "use the slot's preloaded
        // mnemonic").
        let seed_template = seed_secret_template(&seed_buf);
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
/// implement [`HsmBackend`] directly.
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

    /// Tiny stub backend used to verify the attribute-based recipe compiles
    /// cleanly and yields a full [`HsmBackend`] through the blanket impl. The
    /// mechanism numbers are arbitrary but `>= CKM_VENDOR_DEFINED`.
    #[derive(Debug)]
    struct StubBackend;

    impl AttributeDerivation for StubBackend {
        fn backend_name(&self) -> &'static str {
            "stub"
        }
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
    }

    #[test]
    fn trait_object_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn HsmBackend>>();
    }

    #[test]
    fn stub_constants_round_trip() {
        let s = StubBackend;
        // `backend_name` reaches both traits; the blanket forwards it.
        assert_eq!(HsmBackend::backend_name(&s), "stub");
        assert_eq!(AttributeDerivation::backend_name(&s), "stub");
        // Ensure the vendor-defined accessors don't panic.
        let _ = s.master_derive_mechanism();
        let _ = s.child_derive_mechanism();
        let _ = s.chain_code_attribute();
        // The blanket makes the stub usable as a full HsmBackend trait object.
        let _boxed: Box<dyn HsmBackend> = Box::new(StubBackend);
    }
}
