//! [`ThalesBackend`] — `HsmBackend` implementation for Thales ProtectServer
//! (PTK-C) HSMs.
//!
//! Knows the Thales-specific PKCS#11 mechanism IDs and attribute IDs for
//! BIP-32 master and child key derivation. All other behavior — session
//! management, key lookup, ECDSA signing — flows through standard
//! [`cryptoki`].
//!
//! **PKCS#11 library**: `libctsw.so` (PTK-C software emulator) or
//! `libcryptoki.so` (PTK-C hardware client).

use cryptoki::mechanism::MechanismType;
use cryptoki::object::AttributeType;

use super::HsmBackend;

/// Vendor-mechanism ID constants. These are the values Thales PTK-C's
/// BIP-32 extension registers under `CKM_VENDOR_DEFINED`.
const CKM_BIP32_MASTER_DERIVE: u64 = 0x8000_0501;
const CKM_BIP32_CHILD_DERIVE: u64 = 0x8000_0502;

const CKA_BIP32_CHAIN_CODE: u64 = 0x8000_0601;
const CKA_BIP32_DEPTH: u64 = 0x8000_0602;
const CKA_BIP32_PARENT_FINGERPRINT: u64 = 0x8000_0603;
const CKA_BIP32_CHILD_INDEX: u64 = 0x8000_0604;

/// `HsmBackend` implementation for Thales ProtectServer (PTK-C) HSMs.
///
/// All derivation methods inherit from the trait's default implementations
/// — Thales's mechanism parameter struct layout matches the common
/// convention (32-byte seed for master derivation, 4-byte little-endian
/// child index for child derivation). If a future PTK-C release diverges,
/// override the relevant trait methods directly here.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThalesBackend;

impl HsmBackend for ThalesBackend {
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
        "thales"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_thales() {
        assert_eq!(ThalesBackend.backend_name(), "thales");
    }
}
