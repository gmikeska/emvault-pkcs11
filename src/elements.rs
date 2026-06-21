//! [`asterism_elements::ElementsSigner`] implementation for [`Pkcs11Signer`].
//!
//! The HSM produces ECDSA partial signatures over PSET inputs identically
//! to the Bitcoin path: it doesn't see (or care about) confidential
//! transaction data — blinding, range proofs, surjection proofs, and
//! ephemeral keys all stay software-side via `lwk_wollet`. The HSM only
//! computes ECDSA on a sighash.
//!
//! This module mirrors [`crate::signer::Pkcs11Signer`]'s
//! [`bdk_wallet::signer::TransactionSigner`] impl, swapping
//! [`bitcoin::Psbt`] for [`elements::pset::PartiallySignedTransaction`] and
//! [`bitcoin::sighash::SighashCache::p2wsh_signature_hash`] for
//! [`elements::sighash::SighashCache::segwitv0_sighash`].
//!
//! Activated by the `elements` cargo feature on `asterism-pkcs11`, which
//! also activates the matching `elements` feature on `asterism-core`.

use asterism_core::Signer;
use asterism_elements::ElementsSigner;
use asterism_elements::error::PsetError;
use elements::hashes::Hash;
use elements::pset::PartiallySignedTransaction as Pset;
use elements::sighash::SighashCache;

use crate::policy;
use crate::signer::Pkcs11Signer;

impl ElementsSigner for Pkcs11Signer {
    // The mutex guard wraps a `cryptoki::Session` which is `!Sync`, so it
    // genuinely needs to be held across the whole signing flow (sighash
    // computation, per-input signing, and the post-loop sig-rate update
    // all reference `inner.session`).
    #[allow(clippy::significant_drop_tightening)]
    fn sign_pset(&self, pset: &mut Pset) -> Result<usize, PsetError> {
        let inner = self
            .inner_lock()
            .map_err(|e| PsetError::SignerBackend(e.to_string()))?;

        let policy = policy::load_policy(&inner.session, self.label_str())
            .map_err(|e| PsetError::SignerBackend(e.to_string()))?;

        // Sighash computation is over the unsigned-transaction view of the
        // PSET, identical to the bitcoin path. Failure here is a sanity
        // error in the PSET, not an HSM error.
        let unsigned_tx = pset
            .extract_tx()
            .map_err(|e| PsetError::Elements(e.to_string()))?;

        let federation_path_len = self.derivation_path_owned().len();
        let federation_handle = inner.loaded.private_key;
        let mut signed = 0usize;
        for input_idx in 0..pset.inputs().len() {
            let our_origin = pset.inputs()[input_idx]
                .bip32_derivation
                .iter()
                .find(|(_, (fp, _))| *fp == self.fingerprint())
                .map(|(pk, (_, path))| (*pk, path.clone()));

            let Some((our_pk, input_path)) = our_origin else {
                continue;
            };

            let segments: Vec<bitcoin::bip32::ChildNumber> = input_path.as_ref().to_vec();
            if segments.len() < federation_path_len {
                return Err(PsetError::Elements(format!(
                    "input {input_idx} BIP-32 path is shorter than federation path"
                )));
            }
            let relative_segments = &segments[federation_path_len..];
            let relative_path: bitcoin::bip32::DerivationPath = relative_segments.to_vec().into();

            // v1 supports P2WSH (Segwitv0) sighashes only — the same scope
            // as the Bitcoin path. Taproot lands in Phase 2.
            let sighash_type: elements::EcdsaSighashType = pset.inputs()[input_idx]
                .sighash_type
                .and_then(|t| t.ecdsa_hash_ty())
                .unwrap_or(elements::EcdsaSighashType::All);

            let witness_script = pset.inputs()[input_idx]
                .witness_script
                .as_ref()
                .ok_or_else(|| {
                    PsetError::Elements(format!(
                        "input {input_idx} missing witness_script (only P2WSH multi-sig is \
                         supported by Pkcs11Signer in v1)"
                    ))
                })?
                .clone();

            let witness_value = pset.inputs()[input_idx]
                .witness_utxo
                .as_ref()
                .map(|u| u.value)
                .ok_or_else(|| {
                    PsetError::Elements(format!("input {input_idx} missing witness_utxo"))
                })?;

            let sighash = SighashCache::new(&unsigned_tx).segwitv0_sighash(
                input_idx,
                &witness_script,
                witness_value,
                sighash_type,
            );
            let sighash_msg: [u8; 32] = sighash.to_byte_array();

            let signing_handle = if relative_segments.is_empty() {
                federation_handle
            } else {
                inner
                    .backend
                    .derive_path(inner.session.session(), federation_handle, &relative_path)
                    .map_err(|e| PsetError::SignerBackend(e.to_string()))?
            };

            let sign_result = crate::ecdsa::sign_with_low_s(
                inner.session.session(),
                signing_handle,
                &sighash_msg,
            );

            if signing_handle != federation_handle {
                let _ = inner.session.session().destroy_object(signing_handle);
            }

            let mut sig = sign_result.map_err(|e| PsetError::SignerBackend(e.to_string()))?;
            sig.normalize_s();

            // Encode as DER + sighash flag byte (the same wire format
            // bitcoin's PSBT uses; LWK's `Wollet::finalize` consumes
            // exactly this).
            let der = sig.serialize_der();
            let mut sig_bytes = Vec::with_capacity(der.len() + 1);
            sig_bytes.extend_from_slice(&der);
            sig_bytes.push(sighash_type.as_u32() as u8);

            // `our_pk` is already a `bitcoin::PublicKey`: elements PSET
            // input maps use the full bitcoin pubkey (compressed flag +
            // secp256k1 inner). Insert directly.
            pset.inputs_mut()[input_idx]
                .partial_sigs
                .insert(our_pk, sig_bytes);
            signed += 1;
        }

        if signed > 0 {
            policy::check_and_record_sigrate(&inner.session, self.label_str(), &policy)
                .map_err(|e| PsetError::SignerBackend(e.to_string()))?;
        }

        Ok(signed)
    }
}
