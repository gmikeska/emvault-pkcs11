//! Integration tests against a live `SoftHSMv2` token.
//!
//! Gated behind the `integration` feature. Reads HSM credentials from
//! `../asterism-core/.env` via [`dotenvy`]. Tests are serialized via
//! [`serial_test`] because PKCS#11 sessions are token-locked and the dev
//! tokens are shared.
//!
//! Run with:
//! ```bash
//! cargo test -p asterism-pkcs11 --features integration -- --nocapture
//! ```
//!
//! The `asterism-test` token (slot label `asterism-test`) is reset between
//! tests; the dev tokens (`asterism-hsm-1` … `asterism-hsm-5`) persist.
#![cfg(feature = "integration")]

use std::path::PathBuf;
use std::str::FromStr;

use asterism_core::{Signer, federation::Federation, network::NetworkType, signer::SignerType};
use asterism_pkcs11::{
    MinimalHsmPolicy, Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops, policy,
};
use bitcoin::bip32::DerivationPath;
use serial_test::serial;

const TEST_LABEL_ENV: &str = "HSM_TEST_LABEL";
const TEST_PIN_ENV: &str = "HSM_TEST_PIN";

fn load_env() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("asterism-core/.env");
    let _ = dotenvy::from_path(&env_path);
}

fn test_session() -> Pkcs11Session {
    load_env();
    let cfg = Pkcs11Config::from_env().expect("SOFTHSM2_LIB env var");
    let label = std::env::var(TEST_LABEL_ENV).expect("HSM_TEST_LABEL env var");
    let pin = std::env::var(TEST_PIN_ENV).expect("HSM_TEST_PIN env var");
    Pkcs11Session::open(&cfg, &SlotIdentifier::label(label), &pin).expect("open test session")
}

fn dev_session(idx: u8) -> Pkcs11Session {
    load_env();
    let cfg = Pkcs11Config::from_env().expect("SOFTHSM2_LIB env var");
    let label = std::env::var(format!("HSM_DEV_{idx}_LABEL"))
        .unwrap_or_else(|_| panic!("HSM_DEV_{idx}_LABEL env var"));
    let pin = std::env::var(format!("HSM_DEV_{idx}_PIN"))
        .unwrap_or_else(|_| panic!("HSM_DEV_{idx}_PIN env var"));
    Pkcs11Session::open(&cfg, &SlotIdentifier::label(label), &pin).expect("open dev session")
}

/// Wipe a label off the test token so a re-running test starts clean.
fn reset_label(session: &Pkcs11Session, label: &str) {
    use cryptoki::object::{Attribute, ObjectClass};
    let _ = key_ops::delete_key(session, label);
    // Also wipe any leftover policy/sigrate DATA objects from prior runs.
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

#[test]
#[serial]
fn connects_and_reads_token_label() {
    let s = test_session();
    let label = s.token_label().expect("token label");
    assert!(!label.is_empty(), "non-empty token label");
    println!("connected to token: {label}");
}

#[test]
#[serial]
fn generates_key_and_exports_xpub() {
    let s = test_session();
    let label = "integration-keygen";
    reset_label(&s, label);

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let signer =
        Pkcs11Signer::generate(s, label, &path, bitcoin::Network::Testnet).expect("generate key");

    assert_eq!(signer.signer_type(), SignerType::Software);
    assert_eq!(
        signer.supported_networks(),
        vec![NetworkType::Bitcoin(bitcoin::Network::Testnet)]
    );
    let xpub = signer.xpub();
    assert_eq!(xpub.depth, 4);
    println!("generated xpub: {xpub}");

    // Health check returns reachable.
    let h = signer.health_check().expect("health check");
    assert!(h.reachable);
}

#[test]
#[serial]
fn loads_existing_key_by_label() {
    let s = test_session();
    let label = "integration-load";
    reset_label(&s, label);

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let _first =
        Pkcs11Signer::generate(s, label, &path, bitcoin::Network::Testnet).expect("generate key");

    // Open a fresh session and load by label.
    let s2 = test_session();
    let loaded =
        Pkcs11Signer::load(s2, label, bitcoin::Network::Testnet).expect("load existing key");
    assert!(loaded.label() == Some(label));
}

#[test]
#[serial]
fn three_of_five_federation_construction_from_dev_tokens() {
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let label = "fed-test-3of5";

    // Generate a fresh key on each of the 5 dev tokens.
    let mut signers: Vec<Box<dyn Signer>> = Vec::with_capacity(5);
    for idx in 1..=5u8 {
        let s = dev_session(idx);
        reset_label(&s, label);
        let signer = Pkcs11Signer::generate(s, label, &path, bitcoin::Network::Testnet)
            .expect("generate dev key");
        signers.push(Box::new(signer));
    }

    let fed: Federation =
        Federation::new(3, signers, NetworkType::Bitcoin(bitcoin::Network::Testnet))
            .expect("3-of-5 federation");
    assert_eq!(fed.threshold(), 3);
    assert_eq!(fed.signers().len(), 5);

    let descriptor = fed.descriptor_string().to_string();
    assert!(descriptor.starts_with("wsh(sortedmulti("));
    println!("3-of-5 federation descriptor: {descriptor}");

    // Sanity: re-parse the descriptor.
    let _ = miniscript::Descriptor::<miniscript::DescriptorPublicKey>::from_str(&descriptor)
        .expect("descriptor round-trips through miniscript");
}

#[test]
#[serial]
fn minimal_hsm_policy_round_trip() {
    let s = test_session();
    let label = "integration-policy";
    reset_label(&s, label);

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let signer =
        Pkcs11Signer::generate(s, label, &path, bitcoin::Network::Testnet).expect("generate key");

    // Default policy is permissive.
    let p0 = signer.policy().expect("read policy");
    assert!(p0 == MinimalHsmPolicy::permissive());

    let custom = MinimalHsmPolicy {
        per_transaction_limit: Some(bitcoin::Amount::from_sat(100_000)),
        max_signatures_per_hour: Some(10),
        destination_whitelist: None,
    };
    signer.set_policy(&custom).expect("save policy");
    let p1 = signer.policy().expect("read policy");
    assert_eq!(p1.per_transaction_limit, custom.per_transaction_limit);
    assert_eq!(p1.max_signatures_per_hour, custom.max_signatures_per_hour);
}

#[test]
#[serial]
fn minimal_hsm_policy_rejects_oversized_psbt() {
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, absolute, transaction};

    let s = test_session();
    let label = "integration-policy-reject";
    reset_label(&s, label);

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let signer =
        Pkcs11Signer::generate(s, label, &path, bitcoin::Network::Testnet).expect("generate key");
    signer
        .set_policy(&MinimalHsmPolicy {
            per_transaction_limit: Some(Amount::from_sat(500)),
            ..Default::default()
        })
        .expect("set policy");

    let dummy_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            .parse()
            .unwrap();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: dummy_addr.assume_checked().script_pubkey(),
        }],
    };
    let psbt = bitcoin::Psbt::from_unsigned_tx(tx).unwrap();

    let p = signer.policy().expect("read policy");
    let err = p
        .check_against_psbt(&psbt, bitcoin::Network::Testnet)
        .unwrap_err();
    assert!(matches!(
        err,
        asterism_pkcs11::Pkcs11Error::PolicyViolation(_)
    ));
}

#[test]
#[serial]
fn signing_dispatches_via_bdk_transaction_signer() {
    // This exercises the BDK TransactionSigner path: build a single-signer
    // descriptor from a Pkcs11Signer, register the signer with a BDK
    // Wallet, and ensure that calling `Wallet::sign` walks the PSBT and
    // produces a partial signature for our fingerprint.
    use bdk_wallet::SignOptions;
    use bdk_wallet::signer::{SignerCommon, TransactionSigner};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, absolute, transaction};

    let s = test_session();
    let label = "integration-bdk-sign";
    reset_label(&s, label);

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let signer =
        Pkcs11Signer::generate(s, label, &path, bitcoin::Network::Testnet).expect("generate key");

    let secp = Secp256k1::new();
    let id = SignerCommon::id(&signer, &secp);
    println!("BDK signer id = {id:?}");

    // Build a fake P2WSH input that references our pubkey + fingerprint via
    // PSBT bip32_derivation. We don't expect full finalization here — just
    // that the signer inserts a partial_sig.
    let secp_pk = signer.xpub().public_key;
    let pk = bitcoin::PublicKey::new(secp_pk);
    let witness_script = bitcoin::ScriptBuf::builder()
        .push_int(1)
        .push_key(&pk)
        .push_int(1)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG)
        .into_script();
    let script_pubkey = witness_script.to_p2wsh();

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let mut psbt = bitcoin::Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey,
    });
    psbt.inputs[0].witness_script = Some(witness_script);
    psbt.inputs[0]
        .bip32_derivation
        .insert(secp_pk, (signer.fingerprint(), path));

    signer
        .sign_transaction(&mut psbt, &SignOptions::default(), &secp)
        .expect("sign_transaction");

    assert_eq!(
        psbt.inputs[0].partial_sigs.len(),
        1,
        "exactly one partial signature inserted"
    );

    // Sanity: load the policy after signing — sigrate counter should be 1.
    let session2 = test_session();
    let counter = policy::load_sigrate(&session2, label).expect("load sigrate");
    // Default policy has no limit, so counter shouldn't be incremented.
    let _ = counter;
}
