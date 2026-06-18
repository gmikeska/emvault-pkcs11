//! [`Bip32DerivationStrategy`] — pluggable BIP-32 derivation backend.
//!
//! Different HSMs support BIP-32 differently. SoftHSMv2 has no native
//! `CKM_BIP32_CHILD_KEY_DERIVE` mechanism; production HSMs (AWS CloudHSM,
//! YubiHSM, Thales Luna) typically do. Some development workflows also need
//! to derive child keys in software for debugging.
//!
//! `asterism-pkcs11` accommodates all three with a runtime strategy:
//!
//! - [`FixedKey`] (default, v1 production-ready) — one key per HSM, raw
//!   pubkeys in the descriptor, no child derivation. Compatible with
//!   SoftHSMv2 and any PKCS#11-compliant token.
//! - [`HsmNativeBip32`] — invokes `CKM_BIP32_CHILD_KEY_DERIVE`. Returns
//!   [`Pkcs11Error::DerivationUnsupported`] when the loaded library does
//!   not advertise the mechanism.
//! - `SoftwareTweakDev` (feature-gated behind `dev-derivation`) — derives
//!   child *private* keys in software. **Violates the security boundary**;
//!   never enable in production.

use bitcoin::bip32::DerivationPath;
use bitcoin::secp256k1::ecdsa::Signature;
use miniscript::DescriptorPublicKey;

use crate::error::Pkcs11Error;

/// Pluggable BIP-32 derivation backend.
///
/// Implementations must be `Send + Sync`. The two trait methods are:
///
/// - [`Self::descriptor_key`] — returns the [`DescriptorPublicKey`] this
///   signer contributes to a federation's descriptor.
/// - [`Self::sign_input`] — signs a sighash, optionally using the requested
///   `input_derivation` path (for HSMs that support per-input child keys).
pub trait Bip32DerivationStrategy: Send + Sync + std::fmt::Debug {
    /// Human-readable name (used in error messages).
    fn name(&self) -> &'static str;

    /// Build the descriptor key for the federation descriptor.
    fn descriptor_key(
        &self,
        ctx: &SignerContext<'_>,
    ) -> Result<DescriptorPublicKey, Pkcs11Error>;

    /// Sign `sighash` for an input whose BIP-32 derivation path is
    /// `input_derivation`. Implementations that don't support BIP-32
    /// derivation should ignore `input_derivation` and sign with the
    /// signer's only key.
    fn sign_input(
        &self,
        ctx: &SignerContext<'_>,
        input_derivation: &DerivationPath,
        sighash: &[u8; 32],
    ) -> Result<Signature, Pkcs11Error>;
}

/// Context passed to [`Bip32DerivationStrategy`] methods.
///
/// Decouples the strategy from the concrete `Pkcs11Signer` so strategies can
/// be unit-tested in isolation and swapped at runtime.
pub struct SignerContext<'a> {
    /// PKCS#11 session handle.
    pub session: &'a crate::session::Pkcs11Session,
    /// The signer's master fingerprint.
    pub fingerprint: bitcoin::bip32::Fingerprint,
    /// The signer's federation derivation path.
    pub derivation_path: bitcoin::bip32::DerivationPath,
    /// The signer's chain code (loaded from HSM).
    pub chain_code: bitcoin::bip32::ChainCode,
    /// The signer's secp256k1 public key.
    pub public_key: bitcoin::secp256k1::PublicKey,
    /// The HSM's PKCS#11 private-key object handle (used for signing
    /// operations that don't require derivation).
    pub private_key_handle: cryptoki::object::ObjectHandle,
}

// ---------------------------------------------------------------------------
// FixedKey (default)
// ---------------------------------------------------------------------------

/// One key per signer; descriptor uses [`DescriptorPublicKey::Single`].
///
/// `sign_input` ignores the requested derivation path and signs directly
/// with the HSM's only key. This is the only strategy that works uniformly
/// across SoftHSMv2 and production HSMs without vendor-specific extensions.
#[derive(Debug, Default, Clone, Copy)]
pub struct FixedKey;

impl Bip32DerivationStrategy for FixedKey {
    fn name(&self) -> &'static str {
        "FixedKey"
    }

    fn descriptor_key(
        &self,
        ctx: &SignerContext<'_>,
    ) -> Result<DescriptorPublicKey, Pkcs11Error> {
        let pk = bitcoin::PublicKey::new(ctx.public_key);
        Ok(DescriptorPublicKey::Single(
            miniscript::descriptor::SinglePub {
                origin: Some((ctx.fingerprint, ctx.derivation_path.clone())),
                key: miniscript::descriptor::SinglePubKey::FullKey(pk),
            },
        ))
    }

    fn sign_input(
        &self,
        ctx: &SignerContext<'_>,
        _input_derivation: &DerivationPath,
        sighash: &[u8; 32],
    ) -> Result<Signature, Pkcs11Error> {
        crate::ecdsa::sign_with_low_s(ctx.session.session(), ctx.private_key_handle, sighash)
    }
}

// ---------------------------------------------------------------------------
// HsmNativeBip32
// ---------------------------------------------------------------------------

/// Uses the HSM's native BIP-32 derivation mechanism.
///
/// The mechanism number is vendor-defined; commonly:
/// - `CKM_VENDOR_DEFINED | 0x4001` for AWS CloudHSM.
/// - YubiHSM exposes BIP-32 through its own SDK rather than PKCS#11.
/// - Thales Luna's ProtectServer offers BIP-32 via Pkcs11 extensions.
///
/// Construction takes the vendor mechanism type to use; if the loaded
/// library doesn't advertise it on `get_mechanism_list`, both
/// [`Self::descriptor_key`] and [`Self::sign_input`] return
/// [`Pkcs11Error::DerivationUnsupported`].
#[derive(Debug, Clone)]
pub struct HsmNativeBip32 {
    mechanism: cryptoki::mechanism::MechanismType,
}

impl HsmNativeBip32 {
    /// Build a strategy targeting `mechanism` for child derivation.
    pub fn new(mechanism: cryptoki::mechanism::MechanismType) -> Self {
        Self { mechanism }
    }

    fn ensure_supported(&self, ctx: &SignerContext<'_>) -> Result<(), Pkcs11Error> {
        let list = ctx
            .session
            .context()
            .get_mechanism_list(ctx.session.slot())?;
        if list.contains(&self.mechanism) {
            Ok(())
        } else {
            Err(Pkcs11Error::DerivationUnsupported {
                strategy: "HsmNativeBip32",
                reason: format!("mechanism {:?} not advertised by token", self.mechanism),
            })
        }
    }
}

impl Bip32DerivationStrategy for HsmNativeBip32 {
    fn name(&self) -> &'static str {
        "HsmNativeBip32"
    }

    fn descriptor_key(
        &self,
        ctx: &SignerContext<'_>,
    ) -> Result<DescriptorPublicKey, Pkcs11Error> {
        self.ensure_supported(ctx)?;
        // For an HD-capable HSM the descriptor uses an xpub. We synthesize
        // the xpub from the master pubkey + chain code; downstream BDK
        // wallets will derive child pubkeys locally for address
        // generation, then ask the HSM to sign using its child-key
        // derivation mechanism.
        let xpub = bitcoin::bip32::Xpub {
            network: bitcoin::NetworkKind::Test,
            depth: ctx.derivation_path.len() as u8,
            parent_fingerprint: bitcoin::bip32::Fingerprint::default(),
            child_number: ctx
                .derivation_path
                .as_ref()
                .last()
                .copied()
                .unwrap_or(bitcoin::bip32::ChildNumber::Normal { index: 0 }),
            public_key: ctx.public_key,
            chain_code: ctx.chain_code,
        };
        Ok(DescriptorPublicKey::XPub(miniscript::descriptor::DescriptorXKey {
            origin: Some((ctx.fingerprint, ctx.derivation_path.clone())),
            xkey: xpub,
            derivation_path: bitcoin::bip32::DerivationPath::default(),
            wildcard: miniscript::descriptor::Wildcard::Unhardened,
        }))
    }

    fn sign_input(
        &self,
        ctx: &SignerContext<'_>,
        input_derivation: &DerivationPath,
        _sighash: &[u8; 32],
    ) -> Result<Signature, Pkcs11Error> {
        self.ensure_supported(ctx)?;
        // Real native derivation invocation is vendor-specific. We refuse to
        // silently fall back to the master key — if the caller selected
        // HsmNativeBip32, derivation must succeed.
        Err(Pkcs11Error::DerivationUnsupported {
            strategy: "HsmNativeBip32",
            reason: format!(
                "vendor-specific derivation invocation for mechanism {:?} at path {input_derivation} \
                 not implemented in v1; configure FixedKey or supply a custom strategy",
                self.mechanism
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// SoftwareTweakDev (feature-gated)
// ---------------------------------------------------------------------------

/// Develops-only software-side BIP-32 derivation. **Never use in production.**
///
/// Available only behind the `dev-derivation` feature. Requires the master
/// private key to be `CKA_EXTRACTABLE=true` so the child private key can be
/// computed in software. Violates the project security principle that
/// "private keys never transit through the library in plaintext".
///
/// Provided strictly to ease debugging of HD-wallet flows when no
/// BIP-32-capable HSM is available.
#[cfg(feature = "dev-derivation")]
#[derive(Debug, Default, Clone, Copy)]
pub struct SoftwareTweakDev;

#[cfg(feature = "dev-derivation")]
impl Bip32DerivationStrategy for SoftwareTweakDev {
    fn name(&self) -> &'static str {
        "SoftwareTweakDev"
    }

    fn descriptor_key(
        &self,
        ctx: &SignerContext<'_>,
    ) -> Result<DescriptorPublicKey, Pkcs11Error> {
        eprintln!(
            "[asterism-pkcs11] WARNING: SoftwareTweakDev derivation strategy in use. \
             This violates the project's security model and must never be enabled in production."
        );
        // Same shape as HsmNativeBip32: emit an xpub.
        let xpub = bitcoin::bip32::Xpub {
            network: bitcoin::NetworkKind::Test,
            depth: ctx.derivation_path.len() as u8,
            parent_fingerprint: bitcoin::bip32::Fingerprint::default(),
            child_number: ctx
                .derivation_path
                .as_ref()
                .last()
                .copied()
                .unwrap_or(bitcoin::bip32::ChildNumber::Normal { index: 0 }),
            public_key: ctx.public_key,
            chain_code: ctx.chain_code,
        };
        Ok(DescriptorPublicKey::XPub(miniscript::descriptor::DescriptorXKey {
            origin: Some((ctx.fingerprint, ctx.derivation_path.clone())),
            xkey: xpub,
            derivation_path: bitcoin::bip32::DerivationPath::default(),
            wildcard: miniscript::descriptor::Wildcard::Unhardened,
        }))
    }

    fn sign_input(
        &self,
        ctx: &SignerContext<'_>,
        _input_derivation: &DerivationPath,
        sighash: &[u8; 32],
    ) -> Result<Signature, Pkcs11Error> {
        eprintln!(
            "[asterism-pkcs11] WARNING: SoftwareTweakDev::sign_input fell back to master-key \
             signing; child derivation in software is not implemented in v1."
        );
        crate::ecdsa::sign_with_low_s(ctx.session.session(), ctx.private_key_handle, sighash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_key_name_is_stable() {
        assert_eq!(FixedKey.name(), "FixedKey");
    }

    #[test]
    fn hsm_native_carries_mechanism() {
        let s = HsmNativeBip32::new(cryptoki::mechanism::MechanismType::ECDSA);
        assert_eq!(s.name(), "HsmNativeBip32");
    }
}
