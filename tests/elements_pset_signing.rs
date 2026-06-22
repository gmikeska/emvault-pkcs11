//! End-to-end PSET signing tests for the `asterism-pkcs11` → `asterism-elements`
//! integration.
//!
//! Builds a 2-of-3 federation of HSM-backed [`Pkcs11Signer`]s, constructs a
//! synthetic PSET with properly populated inputs (witness_utxo, witness_script,
//! bip32_derivation), and verifies that [`ElementsSigner::sign_pset`] inserts
//! valid ECDSA partial signatures.
//!
//! Unlike the lean descriptor cross-check in
//! `node_pkcs11_elements_cross_check.rs` (which only validates descriptor
//! construction and address derivation), these tests exercise the full signing
//! pipeline: sighash computation → HSM ECDSA → partial_sigs insertion →
//! signature verification.
//!
//! Gated behind `integration` (HSM access) and `elements` (Liquid signer
//! impl). No running Elements node is required — the PSET is constructed
//! synthetically with explicit (unblinded) values.
//!
//! Run with:
//! ```bash
//! cargo test -p asterism-pkcs11 \
//!   --features "integration elements" \
//!   --test elements_pset_signing -- --nocapture
//! ```

#![cfg(all(feature = "integration", feature = "elements"))]

use std::path::PathBuf;
use std::str::FromStr;

use asterism_core::Signer;
use asterism_dev_signer::DevBackend;
use asterism_elements::{CtDescriptorBuilder, ElementsSigner};
use asterism_pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};
use bitcoin::bip32::DerivationPath;
use bitcoin::Network;
use elements::confidential;
use elements::pset::PartiallySignedTransaction as Pset;
use elements::secp256k1_zkp::{Message, Secp256k1};
use serial_test::serial;

// ---------------------------------------------------------------------------
// HSM helpers (same pattern as integration.rs / node_pkcs11_cross_check.rs)
// ---------------------------------------------------------------------------

fn load_env() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("asterism-core/.env");
    let _ = dotenvy::from_path(&env_path);
}

fn dev_session(idx: u8, path: &DerivationPath) -> Pkcs11Session {
    load_env();
    let lib = Pkcs11Config::library_path_from_env().expect("PKCS11_LIB env var");
    let label = std::env::var(format!("HSM_DEV_{idx}_LABEL"))
        .unwrap_or_else(|_| panic!("HSM_DEV_{idx}_LABEL env var"));
    let pin = std::env::var(format!("HSM_DEV_{idx}_PIN"))
        .unwrap_or_else(|_| panic!("HSM_DEV_{idx}_PIN env var"));
    let cfg = Pkcs11Config::new(
        lib,
        SlotIdentifier::label(&label),
        pin.clone(),
        path.clone(),
        Box::new(DevBackend),
    );
    Pkcs11Session::open(&cfg, &SlotIdentifier::label(&label), &pin).expect("open dev session")
}

fn reset_label(session: &Pkcs11Session, label: &str) {
    use cryptoki::object::{Attribute, ObjectClass};
    let _ = key_ops::delete_key(session, label);
    for suffix in ["policy", "sigrate"] {
        let l = format!("asterism/v1/{label}/{suffix}");
        if let Ok(handles) = session.session().find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(l.as_bytes().to_vec()),
        ]) {
            for h in handles {
                let _ = session.session().destroy_object(h);
            }
        }
    }
}

fn make_signers(labels: &[&str], path: &DerivationPath) -> Vec<Pkcs11Signer> {
    labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let idx = u8::try_from(i + 1).expect("test index fits in u8");
            let session = dev_session(idx, path);
            reset_label(&session, label);
            Pkcs11Signer::derive_from_seed(
                session,
                label,
                path,
                Network::Testnet,
                Box::new(DevBackend),
                &[],
            )
            .expect("derive HSM key")
        })
        .collect()
}

/// Build a P2WSH witness script for `sortedmulti(threshold, pk1, pk2, ...)`
/// matching what the descriptor would produce at a given derivation index.
///
/// We manually construct this because we're building a synthetic PSET without
/// a wallet — the test must mirror the same script the descriptor would
/// produce so the sighash matches.
fn build_witness_script(
    threshold: u32,
    pubkeys: &mut [bitcoin::PublicKey],
) -> elements::Script {
    // sortedmulti sorts by the serialized compressed pubkey bytes.
    pubkeys.sort_by_key(|a| a.to_bytes());

    let mut builder = elements::script::Builder::new();
    builder = builder.push_int(i64::from(threshold));
    for pk in pubkeys.iter() {
        builder = builder.push_slice(pk.to_bytes().as_slice());
    }
    builder = builder.push_int(i64::try_from(pubkeys.len()).expect("sane signer count"));
    builder = builder.push_opcode(elements::opcodes::all::OP_CHECKMULTISIG);
    builder.into_script()
}

/// Create a synthetic 1-input, 1-output PSET spending from a P2WSH
/// multi-sig address. The input has:
/// - `witness_utxo` with an explicit (unblinded) value
/// - `witness_script` matching the sortedmulti descriptor
/// - `bip32_derivation` entries for each signer
///
/// This mirrors what LWK's `TxBuilder` produces for a real Elements wallet,
/// but avoids the need for a funded wallet or running node.
fn build_synthetic_pset(
    signers: &[Pkcs11Signer],
    threshold: u32,
    federation_path: &DerivationPath,
) -> Pset {
    use elements::hashes::Hash;
    use elements::pset;

    let input_value_sat: u64 = 100_000;
    let output_value_sat: u64 = 90_000;

    // Collect pubkeys at the federation path (no further derivation — Fixed
    // mode descriptor).
    let mut pubkeys: Vec<bitcoin::PublicKey> = signers
        .iter()
        .map(|s| bitcoin::PublicKey::new(s.xpub().public_key))
        .collect();

    let witness_script = build_witness_script(threshold, &mut pubkeys);
    let script_pubkey = {
        let wsh_hash = elements::WScriptHash::hash(witness_script.as_bytes());
        elements::script::Builder::new()
            .push_int(0)
            .push_slice(wsh_hash.as_ref())
            .into_script()
    };

    // Build a dummy previous transaction that pays to our multi-sig
    // P2WSH address. We need a valid outpoint for the PSET input.
    let prev_tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![elements::TxIn {
            previous_output: elements::OutPoint::null(),
            is_pegin: false,
            script_sig: elements::Script::new(),
            sequence: elements::Sequence::MAX,
            asset_issuance: elements::AssetIssuance::default(),
            witness: elements::TxInWitness::default(),
        }],
        output: vec![elements::TxOut {
            asset: confidential::Asset::Explicit(elements::AssetId::default()),
            value: confidential::Value::Explicit(input_value_sat),
            nonce: confidential::Nonce::Null,
            script_pubkey: script_pubkey.clone(),
            witness: elements::TxOutWitness::default(),
        }],
    };
    let prev_txid = prev_tx.txid();

    // Build the PSET.
    let mut pset = Pset::new_v2();

    // Global: tx version.
    pset.global.tx_data.version = 2;
    pset.global.tx_data.fallback_locktime = Some(elements::LockTime::ZERO);

    // Input.
    let mut pset_input = pset::Input {
        previous_txid: prev_txid,
        previous_output_index: 0,
        sequence: Some(elements::Sequence::MAX),
        witness_utxo: Some(elements::TxOut {
            asset: confidential::Asset::Explicit(elements::AssetId::default()),
            value: confidential::Value::Explicit(input_value_sat),
            nonce: confidential::Nonce::Null,
            script_pubkey: script_pubkey.clone(),
            witness: elements::TxOutWitness::default(),
        }),
        witness_script: Some(witness_script),
        sighash_type: Some(elements::pset::PsbtSighashType::from(
            elements::EcdsaSighashType::All,
        )),
        ..pset::Input::default()
    };

    // BIP-32 derivation entries: one per signer. Use the full federation
    // path as the derivation path with the signer's master fingerprint.
    for signer in signers {
        let pk = bitcoin::PublicKey::new(signer.xpub().public_key);
        pset_input
            .bip32_derivation
            .insert(pk, (signer.fingerprint(), federation_path.clone()));
    }

    pset.add_input(pset_input);

    // Output: pay to a dummy P2WSH (could be anything).
    let pset_output = pset::Output {
        amount: Some(output_value_sat),
        asset: Some(elements::AssetId::default()),
        script_pubkey,
        ..pset::Output::default()
    };
    pset.add_output(pset_output);

    // Fee output (Elements requires an explicit fee output).
    let fee_sat = input_value_sat - output_value_sat;
    let fee_output = pset::Output {
        amount: Some(fee_sat),
        asset: Some(elements::AssetId::default()),
        script_pubkey: elements::Script::new(),
        ..pset::Output::default()
    };
    pset.add_output(fee_output);

    pset
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn pset_signing_2of3_produces_partial_sigs() {
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let labels = [
        "elements-e2e-1",
        "elements-e2e-2",
        "elements-e2e-3",
    ];
    let signers = make_signers(&labels, &path);
    let mut pset = build_synthetic_pset(&signers, 2, &path);

    // Each signer signs independently. After all 3 sign, input 0 should
    // have 3 partial signatures.
    for (i, signer) in signers.iter().enumerate() {
        let count = signer
            .sign_pset(&mut pset)
            .unwrap_or_else(|e| panic!("signer {i} sign_pset failed: {e}"));
        assert_eq!(
            count, 1,
            "signer {i} should have signed exactly 1 input"
        );
    }

    assert_eq!(
        pset.inputs()[0].partial_sigs.len(),
        3,
        "all 3 signers should have inserted partial sigs"
    );
    eprintln!(
        "2-of-3 PSET signing: {} partial signatures on input 0",
        pset.inputs()[0].partial_sigs.len()
    );
}

#[test]
#[serial]
fn pset_partial_sigs_are_valid_ecdsa() {
    let secp = Secp256k1::new();
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let labels = [
        "elements-verify-1",
        "elements-verify-2",
        "elements-verify-3",
    ];
    let signers = make_signers(&labels, &path);
    let mut pset = build_synthetic_pset(&signers, 2, &path);

    for signer in &signers {
        signer
            .sign_pset(&mut pset)
            .expect("sign_pset");
    }

    // Recompute the sighash independently and verify each signature.
    let unsigned_tx = pset
        .extract_tx()
        .expect("extract_tx for sighash verification");

    let witness_script = pset.inputs()[0]
        .witness_script
        .as_ref()
        .expect("witness_script present");
    let witness_value = pset.inputs()[0]
        .witness_utxo
        .as_ref()
        .expect("witness_utxo present")
        .value;
    let sighash = elements::sighash::SighashCache::new(&unsigned_tx).segwitv0_sighash(
        0,
        witness_script,
        witness_value,
        elements::EcdsaSighashType::All,
    );
    let msg = Message::from_digest(elements::hashes::Hash::to_byte_array(sighash));

    for (pk, sig_bytes) in &pset.inputs()[0].partial_sigs {
        // sig_bytes = DER-encoded signature + 1-byte sighash flag.
        assert!(
            sig_bytes.len() > 1,
            "signature bytes too short: {}",
            sig_bytes.len()
        );
        let der_bytes = &sig_bytes[..sig_bytes.len() - 1];
        let sighash_flag = sig_bytes[sig_bytes.len() - 1];
        assert_eq!(
            sighash_flag,
            elements::EcdsaSighashType::All.as_u32() as u8,
            "sighash flag should be SIGHASH_ALL"
        );

        let sig = elements::secp256k1_zkp::ecdsa::Signature::from_der(der_bytes)
            .expect("DER-decode signature");

        // Verify against the public key from the PSET's partial_sigs map.
        secp.verify_ecdsa(&msg, &sig, &pk.inner)
            .unwrap_or_else(|e| panic!("ECDSA verify failed for {pk}: {e}"));
    }

    eprintln!(
        "all {} partial signatures verified against independently computed sighash",
        pset.inputs()[0].partial_sigs.len()
    );
}

#[test]
#[serial]
fn pset_signing_skips_inputs_without_our_fingerprint() {
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let labels = [
        "elements-skip-1",
        "elements-skip-2",
        "elements-skip-3",
    ];
    let signers = make_signers(&labels, &path);
    let mut pset = build_synthetic_pset(&signers, 2, &path);

    // Remove one signer's bip32_derivation from the input — that signer
    // should report 0 inputs signed.
    let removed_fp = signers[2].fingerprint();
    let removed_pk = bitcoin::PublicKey::new(signers[2].xpub().public_key);
    pset.inputs_mut()[0]
        .bip32_derivation
        .remove(&removed_pk);

    let count = signers[2]
        .sign_pset(&mut pset)
        .expect("sign_pset should succeed even when skipping");
    assert_eq!(
        count, 0,
        "signer whose fingerprint was removed should sign 0 inputs"
    );

    // The other two should still sign.
    let c1 = signers[0].sign_pset(&mut pset).expect("signer 0");
    let c2 = signers[1].sign_pset(&mut pset).expect("signer 1");
    assert_eq!(c1, 1);
    assert_eq!(c2, 1);
    assert_eq!(pset.inputs()[0].partial_sigs.len(), 2);
    eprintln!(
        "correctly skipped signer with removed fingerprint ({removed_fp}); \
         2 of 3 signed"
    );
}

#[test]
#[serial]
fn pset_signing_with_ct_descriptor_round_trip() {
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let labels = [
        "elements-ct-1",
        "elements-ct-2",
        "elements-ct-3",
    ];
    let signers = make_signers(&labels, &path);

    // Build a CT descriptor and verify it parses, then sign a PSET built
    // from the same key material. This validates the full pipeline:
    // descriptor construction → PSET construction → HSM signing.
    let mbk = [0xab; 32];
    let mut builder = CtDescriptorBuilder::new(2, &mbk).expect("builder");
    for s in &signers {
        builder.add_signer(s).expect("add signer");
    }
    let ct_desc = builder.build().expect("ct descriptor builds");
    let desc_str = ct_desc.to_string();
    assert!(
        desc_str.starts_with("ct(slip77("),
        "expected ct(slip77(...) prefix, got {desc_str}"
    );

    // Derive a confidential address at index 0.
    let definite = ct_desc.at_derivation_index(0).expect("definite descriptor");
    let secp = asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
    let addr = definite
        .address(
            &secp,
            asterism_elements::ElementsNetwork::LiquidTestnet.address_params(),
        )
        .expect("address derivation");
    assert!(
        addr.blinding_pubkey.is_some(),
        "confidential address should have a blinding pubkey"
    );
    eprintln!("CT descriptor address[0]: {addr}");

    // Now sign a PSET with the same signers.
    let mut pset = build_synthetic_pset(&signers, 2, &path);
    for signer in &signers {
        signer.sign_pset(&mut pset).expect("sign_pset");
    }
    assert_eq!(
        pset.inputs()[0].partial_sigs.len(),
        3,
        "full CT descriptor → PSET signing round trip"
    );
    eprintln!("CT descriptor → PSET signing round trip: OK");
}

#[test]
#[serial]
fn pset_signing_idempotent() {
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let labels = [
        "elements-idem-1",
        "elements-idem-2",
        "elements-idem-3",
    ];
    let signers = make_signers(&labels, &path);
    let mut pset = build_synthetic_pset(&signers, 2, &path);

    // Sign twice with the same signer.
    let c1 = signers[0].sign_pset(&mut pset).expect("first sign");
    let c2 = signers[0].sign_pset(&mut pset).expect("second sign");
    assert_eq!(c1, 1, "first sign should produce 1 signature");
    // Second sign should overwrite the same partial_sig entry (same pubkey
    // key in the map). The count may be 1 (re-signed) — that's fine. What
    // matters is the map has exactly 1 entry, not 2.
    assert_eq!(
        pset.inputs()[0].partial_sigs.len(),
        1,
        "double-sign should not produce duplicate entries"
    );
    eprintln!("idempotent sign: partial_sigs count = 1 after double-sign (c1={c1}, c2={c2})");
}
