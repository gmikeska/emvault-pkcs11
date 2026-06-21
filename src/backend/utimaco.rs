//! [`UtimacoBackend`] — `HsmBackend` implementation for Utimaco Blockchain
//! Protect HSMs.
//!
//! Knows the Utimaco-specific PKCS#11 mechanism IDs and attribute IDs for
//! BIP-32 master and child key derivation. All other behavior — session
//! management, key lookup, ECDSA signing — flows through standard
//! [`cryptoki`].
//!
//! **PKCS#11 library**: `libcs_pkcs11_R3.so` (Utimaco-supplied).

use cryptoki::mechanism::MechanismType;
use cryptoki::object::AttributeType;

use super::HsmBackend;

/// Vendor-mechanism ID constants. These are the values Utimaco's BIP-32
/// SDK registers under `CKM_VENDOR_DEFINED`.
const CKM_BIP32_MASTER_DERIVE: u64 = 0x8000_0001;
const CKM_BIP32_CHILD_DERIVE: u64 = 0x8000_0002;

const CKA_BIP32_CHAIN_CODE: u64 = 0x8000_0101;
const CKA_BIP32_DEPTH: u64 = 0x8000_0102;
const CKA_BIP32_PARENT_FINGERPRINT: u64 = 0x8000_0103;
const CKA_BIP32_CHILD_INDEX: u64 = 0x8000_0104;

/// `HsmBackend` implementation for Utimaco Blockchain Protect HSMs.
///
/// All derivation methods inherit from the trait's default implementations
/// — Utimaco's mechanism parameter struct layout matches the common
/// convention (32-byte seed for master derivation, 4-byte little-endian
/// child index for child derivation). If a future Utimaco SDK release
/// diverges, override the relevant trait methods directly here.
#[derive(Debug, Clone, Copy, Default)]
pub struct UtimacoBackend;

impl HsmBackend for UtimacoBackend {
    fn master_derive_mechanism(&self) -> MechanismType {
        MechanismType::new_vendor_defined(CKM_BIP32_MASTER_DERIVE)
            .expect("CKM_BIP32_MASTER_DERIVE >= CKM_VENDOR_DEFINED")
    }

    fn child_derive_mechanism(&self) -> MechanismType {
        MechanismType::new_vendor_defined(CKM_BIP32_CHILD_DERIVE)
            .expect("CKM_BIP32_CHILD_DERIVE >= CKM_VENDOR_DEFINED")
    }

    fn chain_code_attribute(&self) -> AttributeType {
        AttributeType::VendorDefined(CKA_BIP32_CHAIN_CODE)
    }

    fn depth_attribute(&self) -> AttributeType {
        AttributeType::VendorDefined(CKA_BIP32_DEPTH)
    }

    fn parent_fingerprint_attribute(&self) -> AttributeType {
        AttributeType::VendorDefined(CKA_BIP32_PARENT_FINGERPRINT)
    }

    fn child_index_attribute(&self) -> AttributeType {
        AttributeType::VendorDefined(CKA_BIP32_CHILD_INDEX)
    }

    fn backend_name(&self) -> &str {
        "utimaco"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_utimaco() {
        assert_eq!(UtimacoBackend.backend_name(), "utimaco");
    }
}
