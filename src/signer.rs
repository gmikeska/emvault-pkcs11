//! [`Pkcs11Signer`] — the PKCS#11-backed implementation of
//! [`asterism_core::Signer`] and [`bdk_wallet::signer::TransactionSigner`].
//!
//! `Pkcs11Signer` is the v1 production-ready signer backend for HSM
//! federations. It wraps a [`Pkcs11Session`] in an internal `Arc<Mutex<...>>`
//! so the type is `Send + Sync` (cryptoki's `Session` is deliberately
//! `!Sync`).

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use asterism_core::{
    Signer, SignerCapabilities, SignerId, SignerType, TransportType, error::SignerError,
    network::NetworkType, signer::SignerHealth,
};
use bdk_wallet::SignOptions;
use bdk_wallet::signer::{
    SignerCommon, SignerError as BdkSignerError, SignerId as BdkSignerId, TransactionSigner,
};
use bitcoin::Psbt;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use miniscript::DescriptorPublicKey;

use crate::derivation::{Bip32DerivationStrategy, FixedKey, SignerContext};
use crate::error::Pkcs11Error;
use crate::key_ops::{self, LoadedKey};
use crate::policy::{self, MinimalHsmPolicy};
use crate::session::Pkcs11Session;

/// PKCS#11-backed `Signer`.
///
/// Cheap to clone (an inner `Arc<Mutex<...>>` is shared across clones; the
/// underlying HSM session is *not* duplicated).
pub struct Pkcs11Signer {
    label: String,
    id: SignerId,
    fingerprint: Fingerprint,
    derivation_path: DerivationPath,
    xpub: Xpub,
    network: bitcoin::Network,
    capabilities: SignerCapabilities,
    descriptor_key: DescriptorPublicKey,
    inner: Arc<Mutex<Pkcs11SignerInner>>,
}

struct Pkcs11SignerInner {
    session: Pkcs11Session,
    loaded: LoadedKey,
    derivation: Box<dyn Bip32DerivationStrategy>,
}

impl std::fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("label", &self.label)
            .field("id", &self.id)
            .field("fingerprint", &self.fingerprint)
            .field("derivation_path", &self.derivation_path)
            .field("network", &self.network)
            .finish()
    }
}

impl Clone for Pkcs11Signer {
    fn clone(&self) -> Self {
        Self {
            label: self.label.clone(),
            id: self.id.clone(),
            fingerprint: self.fingerprint,
            derivation_path: self.derivation_path.clone(),
            xpub: self.xpub,
            network: self.network,
            capabilities: self.capabilities.clone(),
            descriptor_key: self.descriptor_key.clone(),
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Pkcs11Signer {
    /// Create a fresh signer (generates a new keypair on the HSM).
    ///
    /// Uses [`FixedKey`] as the derivation strategy by default — see
    /// [`Self::with_strategy`] to override.
    pub fn generate(
        session: Pkcs11Session,
        label: &str,
        derivation_path: &DerivationPath,
        network: bitcoin::Network,
    ) -> Result<Self, Pkcs11Error> {
        let loaded = key_ops::generate_key(&session, label, derivation_path, network)?;
        Self::from_loaded(session, label, loaded, network, Box::new(FixedKey))
    }

    /// Load an existing signer by label.
    pub fn load(
        session: Pkcs11Session,
        label: &str,
        network: bitcoin::Network,
    ) -> Result<Self, Pkcs11Error> {
        let loaded = key_ops::find_key_by_label(&session, label)?
            .ok_or_else(|| Pkcs11Error::ObjectNotFound(format!("key with label {label}")))?;
        Self::from_loaded(session, label, loaded, network, Box::new(FixedKey))
    }

    /// Construct from an already-loaded key with a custom derivation
    /// strategy. Useful for production HSMs that need
    /// [`crate::HsmNativeBip32`].
    pub fn with_strategy(
        session: Pkcs11Session,
        label: &str,
        loaded: LoadedKey,
        network: bitcoin::Network,
        strategy: Box<dyn Bip32DerivationStrategy>,
    ) -> Result<Self, Pkcs11Error> {
        Self::from_loaded(session, label, loaded, network, strategy)
    }

    fn from_loaded(
        session: Pkcs11Session,
        label: &str,
        loaded: LoadedKey,
        network: bitcoin::Network,
        derivation: Box<dyn Bip32DerivationStrategy>,
    ) -> Result<Self, Pkcs11Error> {
        let xpub = key_ops::derive_xpub(&loaded)?;
        let fingerprint = loaded.material.fingerprint()?;
        let derivation_path = loaded.material.derivation_path()?;

        // Build descriptor key via the strategy.
        let ctx = SignerContext {
            session: &session,
            fingerprint,
            derivation_path: derivation_path.clone(),
            chain_code: loaded.material.chain_code()?,
            public_key: loaded.public_key,
            private_key_handle: loaded.private_key,
        };
        let descriptor_key = derivation.descriptor_key(&ctx)?;

        let capabilities = SignerCapabilities {
            blind_signing: false,
            taproot: true,
            musig2: false,
            transports: vec![TransportType::Pkcs11],
        };
        let id = SignerId::from_fingerprint(fingerprint);

        let inner = Pkcs11SignerInner {
            session,
            loaded,
            derivation,
        };
        Ok(Self {
            label: label.to_string(),
            id,
            fingerprint,
            derivation_path,
            xpub,
            network,
            capabilities,
            descriptor_key,
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// The descriptor key this signer contributes to a federation
    /// descriptor.
    pub fn descriptor_key(&self) -> &DescriptorPublicKey {
        &self.descriptor_key
    }

    /// Read the HSM-resident [`MinimalHsmPolicy`].
    pub fn policy(&self) -> Result<MinimalHsmPolicy, Pkcs11Error> {
        let inner = self.inner.lock().expect("Pkcs11Signer mutex poisoned");
        policy::load_policy(&inner.session, &self.label)
    }

    /// Replace the HSM-resident policy.
    pub fn set_policy(&self, p: &MinimalHsmPolicy) -> Result<(), Pkcs11Error> {
        let inner = self.inner.lock().expect("Pkcs11Signer mutex poisoned");
        policy::save_policy(&inner.session, &self.label, p).map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// asterism_core::Signer
// ---------------------------------------------------------------------------

impl Signer for Pkcs11Signer {
    fn id(&self) -> SignerId {
        self.id.clone()
    }
    fn label(&self) -> Option<&str> {
        Some(&self.label)
    }
    fn xpub(&self) -> &Xpub {
        &self.xpub
    }
    fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
    fn derivation_path(&self) -> &DerivationPath {
        &self.derivation_path
    }
    fn signer_type(&self) -> SignerType {
        SignerType::Software
    }
    fn supported_networks(&self) -> Vec<NetworkType> {
        vec![NetworkType::Bitcoin(self.network)]
    }
    fn capabilities(&self) -> SignerCapabilities {
        self.capabilities.clone()
    }
    fn health_check(&self) -> Result<SignerHealth, SignerError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| SignerError::Backend("Pkcs11Signer mutex poisoned".into()))?;
        let label = inner
            .session
            .token_label()
            .map_err(|e| SignerError::from(e))?;
        Ok(SignerHealth {
            reachable: true,
            firmware_version: Some(format!("pkcs11/{label}")),
            last_seen: Some(SystemTime::now()),
        })
    }
}

// ---------------------------------------------------------------------------
// bdk_wallet::signer::TransactionSigner
// ---------------------------------------------------------------------------

impl SignerCommon for Pkcs11Signer {
    fn id(&self, _secp: &Secp256k1<All>) -> BdkSignerId {
        BdkSignerId::Fingerprint(self.fingerprint)
    }
}

impl TransactionSigner for Pkcs11Signer {
    fn sign_transaction(
        &self,
        psbt: &mut Psbt,
        _sign_options: &SignOptions,
        _secp: &Secp256k1<All>,
    ) -> Result<(), BdkSignerError> {
        // 1) Lock the inner state.
        let inner = self
            .inner
            .lock()
            .map_err(|_| BdkSignerError::External("Pkcs11Signer mutex poisoned".into()))?;

        // 2) Enforce HSM-local policy before any signing.
        let policy = policy::load_policy(&inner.session, &self.label)
            .map_err(|e| BdkSignerError::External(e.to_string()))?;
        policy
            .check_against_psbt(psbt, self.network)
            .map_err(|e| BdkSignerError::External(e.to_string()))?;

        // 3) Build the per-signer SignerContext once.
        let chain_code = inner
            .loaded
            .material
            .chain_code()
            .map_err(|e| BdkSignerError::External(e.to_string()))?;
        let signer_ctx = SignerContext {
            session: &inner.session,
            fingerprint: self.fingerprint,
            derivation_path: self.derivation_path.clone(),
            chain_code,
            public_key: inner.loaded.public_key,
            private_key_handle: inner.loaded.private_key,
        };

        // 4) Walk the PSBT inputs, signing those that reference this signer.
        let mut signed_any = false;
        for input_idx in 0..psbt.inputs.len() {
            // Find a key in this input whose origin matches our fingerprint.
            let our_origin = psbt.inputs[input_idx]
                .bip32_derivation
                .iter()
                .find(|(_, (fp, _))| *fp == self.fingerprint)
                .map(|(pk, (_, path))| (*pk, path.clone()));

            let Some((our_pk, input_path)) = our_origin else {
                continue;
            };

            // Compute sighash. v1 supports P2WSH (Segwitv0) only — the
            // common case for asterism federations.
            let sighash_type = psbt.inputs[input_idx]
                .sighash_type
                .map(|t| t.ecdsa_hash_ty())
                .transpose()
                .map_err(|e| BdkSignerError::External(format!("invalid sighash type: {e}")))?
                .unwrap_or(EcdsaSighashType::All);

            let witness_script = psbt.inputs[input_idx]
                .witness_script
                .as_ref()
                .ok_or_else(|| {
                    BdkSignerError::External(format!(
                        "input {input_idx} missing witness_script (only P2WSH multi-sig is \
                         supported by Pkcs11Signer in v1)"
                    ))
                })?
                .clone();

            let witness_utxo_value = psbt.inputs[input_idx]
                .witness_utxo
                .as_ref()
                .map(|u| u.value)
                .ok_or_else(|| {
                    BdkSignerError::External(format!("input {input_idx} missing witness_utxo"))
                })?;

            let sighash = SighashCache::new(&psbt.unsigned_tx)
                .p2wsh_signature_hash(input_idx, &witness_script, witness_utxo_value, sighash_type)
                .map_err(|e| BdkSignerError::External(format!("sighash failure: {e}")))?;
            let sighash_msg: [u8; 32] = sighash.to_byte_array();

            // Sign via the strategy.
            let mut sig = inner
                .derivation
                .sign_input(&signer_ctx, &input_path, &sighash_msg)
                .map_err(|e| BdkSignerError::External(e.to_string()))?;
            // Belt-and-suspenders: ensure low-S even if strategy didn't.
            sig.normalize_s();

            let bitcoin_sig = bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type,
            };
            let pk = bitcoin::PublicKey::new(our_pk);
            psbt.inputs[input_idx].partial_sigs.insert(pk, bitcoin_sig);
            signed_any = true;
        }

        // 5) Update the sig-rate counter only if at least one input was signed.
        if signed_any {
            policy::check_and_record_sigrate(&inner.session, &self.label, &policy)
                .map_err(|e| BdkSignerError::External(e.to_string()))?;
        }

        Ok(())
    }
}
