//! [`Pkcs11Signer`] — the HSM-backed implementation of
//! [`emvault_core::Signer`] and [`bdk_wallet::signer::TransactionSigner`].
//!
//! `Pkcs11Signer` owns a [`Pkcs11Session`] and a
//! [`Box<dyn HsmBackend>`](crate::backend::HsmBackend). The backend is the
//! only piece of vendor-specific knowledge the signer carries; everything
//! else is plain [`cryptoki`].
//!
//! ## Lifecycle
//!
//! There are two ways to materialize a signer:
//!
//! - [`Pkcs11Signer::derive_from_seed`] — the **key ceremony** path. Calls
//!   `backend.derive_master_key()` + `backend.derive_path()` to create the
//!   federation key inside the HSM, then `backend.read_xpub()` to read the
//!   federation xpub for descriptor construction. Private keys never
//!   leave the HSM; only the seed transits through the call (and only
//!   long enough to feed it into `C_DeriveKey`).
//! - [`Pkcs11Signer::load`] — the **operational** path. Looks up an
//!   already-derived key by EmVault label and reads its xpub via
//!   `backend.read_xpub()`. The HSM is the source of truth for the
//!   chain code and the rest of the BIP-32 metadata.
//!
//! ## Send + Sync
//!
//! `cryptoki::Session` is `!Sync` for good reasons (tokens are
//! single-threaded). `Pkcs11Signer` wraps an inner mutex around the
//! session so the public type is `Send + Sync` for use in async contexts.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bdk_wallet::SignOptions;
use bdk_wallet::signer::{
    SignerCommon, SignerError as BdkSignerError, SignerId as BdkSignerId, TransactionSigner,
};
use bitcoin::Psbt;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use emvault_core::{
    Signer, SignerCapabilities, SignerId, SignerType, TransportType, error::SignerError,
    network::NetworkType, signer::SignerHealth,
};
use miniscript::DescriptorPublicKey;

use crate::backend::HsmBackend;
use crate::error::Pkcs11Error;
use crate::key_ops::{self, LoadedKey};
use crate::policy::{self, MinimalHsmPolicy};
use crate::session::Pkcs11Session;

/// HSM-backed `Signer`.
///
/// Cheap to clone — clones share the underlying `Arc<Mutex<...>>`, so the
/// HSM session is **not** duplicated. Use a fresh [`Pkcs11Session`] if you
/// need parallel signing throughput.
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

pub(crate) struct Pkcs11SignerInner {
    pub(crate) session: Pkcs11Session,
    pub(crate) loaded: LoadedKey,
    pub(crate) backend: Box<dyn HsmBackend>,
}

impl std::fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("label", &self.label)
            .field("id", &self.id)
            .field("fingerprint", &self.fingerprint)
            .field("derivation_path", &self.derivation_path)
            .field("xpub", &self.xpub)
            .field("network", &self.network)
            .field("capabilities", &self.capabilities)
            .field("descriptor_key", &self.descriptor_key)
            .finish_non_exhaustive()
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
    /// Derive a fresh federation key on the HSM from `seed`.
    ///
    /// This is the key-ceremony entry point. The flow is:
    ///
    /// 1. `backend.derive_master_key(seed)` — creates the master private
    ///    key on the token via vendor `C_DeriveKey`.
    /// 2. `backend.derive_path(master, path)` — derives the federation
    ///    path one segment at a time inside the HSM.
    /// 3. `backend.read_xpub(final_handle)` — reads the federation xpub
    ///    via `CKA_EC_POINT` plus vendor BIP-32 attributes.
    ///
    /// Private keys never leave the HSM. The seed transits through the
    /// caller's stack only as long as it takes to feed it into
    /// `C_DeriveKey`.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if any HSM call fails or the resulting key
    /// cannot be read back as a valid xpub.
    pub fn derive_from_seed(
        session: Pkcs11Session,
        label: &str,
        derivation_path: &DerivationPath,
        network: bitcoin::Network,
        backend: Box<dyn HsmBackend>,
        seed: &[u8],
    ) -> Result<Self, Pkcs11Error> {
        let priv_label = key_ops::priv_label(label);
        let master = backend
            .derive_master_key(session.session(), seed, &priv_label)
            .map_err(Pkcs11Error::from)?;
        let final_handle = backend
            .derive_path(session.session(), master.key_handle, derivation_path)
            .map_err(Pkcs11Error::from)?;
        let xpub = backend
            .read_xpub(session.session(), final_handle)
            .map_err(Pkcs11Error::from)?;
        let fingerprint = master.fingerprint;
        let loaded = LoadedKey {
            private_key: final_handle,
        };
        Ok(Self::from_loaded(
            session,
            label,
            loaded,
            xpub,
            fingerprint,
            derivation_path.clone(),
            network,
            backend,
        ))
    }

    /// Load an existing federation key by label.
    ///
    /// The HSM is the source of truth for the chain code and BIP-32
    /// metadata; this constructor reads `CKA_EC_POINT` plus the vendor
    /// BIP-32 attributes via `backend.read_xpub()`.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error::ObjectNotFound`] if no key with `label`
    /// exists, or any other [`Pkcs11Error`] surfaced by the underlying
    /// token.
    pub fn load(
        session: Pkcs11Session,
        label: &str,
        derivation_path: DerivationPath,
        network: bitcoin::Network,
        backend: Box<dyn HsmBackend>,
    ) -> Result<Self, Pkcs11Error> {
        let loaded = key_ops::find_key_by_label(&session, label)?
            .ok_or_else(|| Pkcs11Error::ObjectNotFound(format!("key with label {label}")))?;
        let xpub = backend
            .read_xpub(session.session(), loaded.private_key)
            .map_err(Pkcs11Error::from)?;
        let fingerprint = backend
            .master_fingerprint(session.session(), loaded.private_key)
            .map_err(Pkcs11Error::from)?;
        Ok(Self::from_loaded(
            session,
            label,
            loaded,
            xpub,
            fingerprint,
            derivation_path,
            network,
            backend,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_loaded(
        session: Pkcs11Session,
        label: &str,
        loaded: LoadedKey,
        xpub: Xpub,
        fingerprint: Fingerprint,
        derivation_path: DerivationPath,
        network: bitcoin::Network,
        backend: Box<dyn HsmBackend>,
    ) -> Self {
        let descriptor_key = build_descriptor_key(&xpub, fingerprint, &derivation_path);

        let capabilities = SignerCapabilities {
            // `blind_signing` advertises that the signer can produce
            // signatures over confidential-transaction sighashes. The HSM's
            // ECDSA path is identical for Bitcoin and Liquid; LWK does the
            // actual blinding software-side. We advertise the capability
            // whenever the `elements` feature is compiled in.
            blind_signing: cfg!(feature = "elements"),
            taproot: true,
            musig2: false,
            transports: vec![TransportType::Pkcs11],
        };
        let id = SignerId::from_fingerprint(fingerprint);

        let inner = Pkcs11SignerInner {
            session,
            loaded,
            backend,
        };
        Self {
            label: label.to_string(),
            id,
            fingerprint,
            derivation_path,
            xpub,
            network,
            capabilities,
            descriptor_key,
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// The descriptor key this signer contributes to a federation
    /// descriptor.
    pub fn descriptor_key(&self) -> &DescriptorPublicKey {
        &self.descriptor_key
    }

    /// Borrow the signer's label as a `&str`. Internal helper for crate
    /// modules that need it without a clone.
    #[cfg(feature = "elements")]
    pub(crate) fn label_str(&self) -> &str {
        &self.label
    }

    /// Owned clone of the derivation path. Internal helper for crate
    /// modules that build a per-network signer impl on top of the same
    /// HSM session.
    #[cfg(feature = "elements")]
    pub(crate) fn derivation_path_owned(&self) -> DerivationPath {
        self.derivation_path.clone()
    }

    /// Lock the inner mutex. Internal helper exposed only to crate
    /// modules so the per-network Elements signer impl can share the same
    /// session/key bundle.
    #[cfg(feature = "elements")]
    pub(crate) fn inner_lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Pkcs11SignerInner>, &'static str> {
        self.inner.lock().map_err(|_| "Pkcs11Signer mutex poisoned")
    }

    /// Read the HSM-resident [`MinimalHsmPolicy`].
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if the policy object is missing, malformed,
    /// or the underlying token can't be queried.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only possible if a
    /// previous caller panicked while holding the lock).
    pub fn policy(&self) -> Result<MinimalHsmPolicy, Pkcs11Error> {
        let inner = self.inner.lock().expect("Pkcs11Signer mutex poisoned");
        policy::load_policy(&inner.session, &self.label)
    }

    /// Replace the HSM-resident policy.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if the underlying token rejects the write
    /// or the policy serialization fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only possible if a
    /// previous caller panicked while holding the lock).
    pub fn set_policy(&self, p: &MinimalHsmPolicy) -> Result<(), Pkcs11Error> {
        let inner = self.inner.lock().expect("Pkcs11Signer mutex poisoned");
        policy::save_policy(&inner.session, &self.label, p).map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Descriptor key construction
// ---------------------------------------------------------------------------

/// Build a `DescriptorPublicKey::XPub` for the federation descriptor.
///
/// Uses an unhardened `/0/*` wildcard so BDK can derive child
/// receive/change addresses from the federation xpub. The signer contributes
/// the xpub at the federation's own derivation path; BDK and miniscript
/// handle child derivation locally for address generation, then the HSM
/// signs each input via standard `CKM_ECDSA`.
fn build_descriptor_key(
    xpub: &Xpub,
    fingerprint: Fingerprint,
    derivation_path: &DerivationPath,
) -> DescriptorPublicKey {
    DescriptorPublicKey::XPub(miniscript::descriptor::DescriptorXKey {
        origin: Some((fingerprint, derivation_path.clone())),
        xkey: *xpub,
        derivation_path: DerivationPath::default(),
        wildcard: miniscript::descriptor::Wildcard::Unhardened,
    })
}

// ---------------------------------------------------------------------------
// emvault_core::Signer
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
        // When the `elements` feature is on, also advertise the matching
        // Elements network. HSMs sign with the same secp256k1 key for
        // both — the difference between Bitcoin and Liquid is purely
        // script/address-format. This lets one `Pkcs11Signer` participate
        // in either network without a separate constructor.
        #[cfg(feature = "elements")]
        {
            let mut networks = vec![NetworkType::Bitcoin(self.network)];
            let id = match self.network {
                bitcoin::Network::Bitcoin => Some(emvault_core::ElementsNetworkId::Liquid),
                bitcoin::Network::Testnet => Some(emvault_core::ElementsNetworkId::LiquidTestnet),
                bitcoin::Network::Regtest => Some(emvault_core::ElementsNetworkId::ElementsRegtest),
                _ => None,
            };
            if let Some(id) = id {
                networks.push(NetworkType::Elements(id));
            }
            networks
        }
        #[cfg(not(feature = "elements"))]
        vec![NetworkType::Bitcoin(self.network)]
    }
    fn capabilities(&self) -> SignerCapabilities {
        self.capabilities.clone()
    }
    fn health_check(&self) -> Result<SignerHealth, SignerError> {
        let label = {
            let inner = self
                .inner
                .lock()
                .map_err(|_| SignerError::Backend("Pkcs11Signer mutex poisoned".into()))?;
            inner.session.token_label().map_err(SignerError::from)?
        };
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
    // The mutex guard wraps a `cryptoki::Session` which is `!Sync`, so it
    // genuinely needs to be held across the whole signing flow.
    #[allow(clippy::significant_drop_tightening)]
    fn sign_transaction(
        &self,
        psbt: &mut Psbt,
        _sign_options: &SignOptions,
        _secp: &Secp256k1<All>,
    ) -> Result<(), BdkSignerError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| BdkSignerError::External("Pkcs11Signer mutex poisoned".into()))?;

        let policy = policy::load_policy(&inner.session, &self.label)
            .map_err(|e| BdkSignerError::External(e.to_string()))?;
        policy
            .check_against_psbt(psbt, self.network)
            .map_err(|e| BdkSignerError::External(e.to_string()))?;

        let federation_handle = inner.loaded.private_key;
        let federation_path_len = self.derivation_path.len();
        let mut signed_any = false;

        for input_idx in 0..psbt.inputs.len() {
            let our_origin = psbt.inputs[input_idx]
                .bip32_derivation
                .iter()
                .find(|(_, (fp, _))| *fp == self.fingerprint)
                .map(|(pk, (_, path))| (*pk, path.clone()));

            let Some((our_pk, input_path)) = our_origin else {
                continue;
            };

            // The PSBT input path is full from the master fingerprint:
            // e.g. m/48'/1'/0'/2'/0/5. Strip the federation prefix and
            // ask the HSM to derive the suffix (typically /change/idx)
            // from the federation key handle.
            let segments: Vec<bitcoin::bip32::ChildNumber> = input_path.as_ref().to_vec();
            if segments.len() < federation_path_len {
                return Err(BdkSignerError::External(format!(
                    "input {input_idx} BIP-32 path {input_path} is shorter than this signer's \
                     federation path {}",
                    self.derivation_path
                )));
            }
            let relative_segments = &segments[federation_path_len..];
            let relative_path: bitcoin::bip32::DerivationPath = relative_segments.to_vec().into();

            // v1 supports P2WSH (Segwitv0) sighashes only — the common case
            // for EmVault federations.
            let sighash_type = psbt.inputs[input_idx]
                .sighash_type
                .map(bitcoin::psbt::PsbtSighashType::ecdsa_hash_ty)
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

            // Derive a session-scoped child key handle for this input's
            // BIP-32 path (typically `/change/index`). When the relative
            // path is empty the federation handle itself signs.
            let signing_handle = if relative_segments.is_empty() {
                federation_handle
            } else {
                inner
                    .backend
                    .derive_path(inner.session.session(), federation_handle, &relative_path)
                    .map_err(|e| BdkSignerError::External(e.to_string()))?
            };

            let sign_result = crate::ecdsa::sign_with_low_s(
                inner.session.session(),
                signing_handle,
                &sighash_msg,
            );

            // Best-effort cleanup: destroy session-only child keys after
            // signing. Errors are non-fatal — the token will reap them on
            // session close.
            if signing_handle != federation_handle {
                let _ = inner.session.session().destroy_object(signing_handle);
            }

            let mut sig = sign_result.map_err(|e| BdkSignerError::External(e.to_string()))?;
            sig.normalize_s();

            let bitcoin_sig = bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type,
            };
            let pk = bitcoin::PublicKey::new(our_pk);
            psbt.inputs[input_idx].partial_sigs.insert(pk, bitcoin_sig);
            signed_any = true;
        }

        if signed_any {
            policy::check_and_record_sigrate(&inner.session, &self.label, &policy)
                .map_err(|e| BdkSignerError::External(e.to_string()))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Network-patched signer wrapper
// ---------------------------------------------------------------------------

/// Adapter around [`Pkcs11Signer`] that re-stamps the xpub network kind.
///
/// The dev-shim backend (and the default `HsmBackend::read_xpub`
/// implementation) always reports an xpub with `NetworkKind::Main`, while a
/// wallet may run on `Network::Regtest`/`Testnet`. `DescriptorBuilder` rejects
/// that mismatch with `DescriptorError::NetworkMismatch`. This wrapper carries a
/// cloned xpub with the `network` field corrected so federation construction
/// succeeds; the underlying chain code, public key, and BIP-32 metadata are
/// untouched, and the actual `cryptoki` signing path still runs through the
/// inner [`Pkcs11Signer`] (registered separately on `bdk_wallet::Wallet` via
/// `add_signer`). Any PKCS#11 consumer on a non-mainnet network needs this.
#[derive(Clone, Debug)]
pub struct NetworkPatchedSigner {
    inner: Pkcs11Signer,
    patched_xpub: Xpub,
}

impl NetworkPatchedSigner {
    /// Wrap `inner` with an xpub network kind matching `network`.
    #[must_use]
    pub fn new(inner: Pkcs11Signer, network: bitcoin::Network) -> Self {
        let mut xpub = *inner.xpub();
        xpub.network = bitcoin::NetworkKind::from(network);
        Self {
            inner,
            patched_xpub: xpub,
        }
    }

    /// Borrow the inner [`Pkcs11Signer`].
    #[must_use]
    pub fn inner(&self) -> &Pkcs11Signer {
        &self.inner
    }
}

impl Signer for NetworkPatchedSigner {
    fn id(&self) -> SignerId {
        // `Pkcs11Signer` also impls bdk's `SignerCommon::id` (both traits are in
        // scope in this module), so disambiguate to the core `Signer` trait.
        Signer::id(&self.inner)
    }
    fn label(&self) -> Option<&str> {
        self.inner.label()
    }
    fn xpub(&self) -> &Xpub {
        &self.patched_xpub
    }
    fn fingerprint(&self) -> Fingerprint {
        self.inner.fingerprint()
    }
    fn derivation_path(&self) -> &DerivationPath {
        self.inner.derivation_path()
    }
    fn signer_type(&self) -> SignerType {
        self.inner.signer_type()
    }
    fn supported_networks(&self) -> Vec<NetworkType> {
        self.inner.supported_networks()
    }
    fn capabilities(&self) -> SignerCapabilities {
        self.inner.capabilities()
    }
    fn health_check(&self) -> Result<SignerHealth, SignerError> {
        self.inner.health_check()
    }
}
