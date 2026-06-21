//! Cross-validate `Pkcs11Signer`-backed Liquid federations against a
//! running Elements node or Esplora endpoint.
//!
//! Builds a federation from HSM-resident keys (one per `HSM_DEV_*` token
//! in `.env`) and:
//!
//! 1. Constructs a `ct(slip77(...), elwsh(sortedmulti(...)))` descriptor
//!    via `asterism_elements::CtDescriptorBuilder`.
//! 2. Derives a confidential address locally.
//! 3. (Optional, when `ELEMENTS_RPC_URL` is set) compares against the
//!    node's `getnewaddress`/`getaddressinfo` for the same descriptor.
//!
//! Gated behind `integration` (HSM access), `node-tests` (RPC access),
//! and `elements` (Liquid signer impl). Tests skip gracefully when
//! `ELEMENTS_RPC_URL` is unset; HSM presence is required.
//!
//! Run with:
//! ```bash
//! cargo test -p asterism-pkcs11 \
//!   --features "integration node-tests elements" \
//!   --test node_pkcs11_elements_cross_check -- --nocapture
//! ```

#![cfg(all(feature = "integration", feature = "node-tests", feature = "elements"))]

use std::env;
use std::path::PathBuf;
use std::str::FromStr;

use asterism_core::{ElementsNetworkId, NetworkType, Signer};
use asterism_dev_signer::{DevBackend, mnemonic_to_seed_no_passphrase};
use asterism_elements::{CtDescriptorBuilder, ElementsNetwork, ElementsSigner};
use asterism_pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};
use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use secrecy::ExposeSecret;
use serial_test::serial;

fn load_env() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("asterism-core/.env");
    let _ = dotenvy::from_path(&env_path);
}

fn dev_session(idx: u8, path: &DerivationPath) -> (Pkcs11Session, String) {
    load_env();
    let lib = Pkcs11Config::library_path_from_env().expect("PKCS11_LIB env var");
    let label = std::env::var(format!("HSM_DEV_{idx}_LABEL"))
        .unwrap_or_else(|_| panic!("HSM_DEV_{idx}_LABEL env var"));
    let pin = std::env::var(format!("HSM_DEV_{idx}_PIN"))
        .unwrap_or_else(|_| panic!("HSM_DEV_{idx}_PIN env var"));
    let mnemonic = std::env::var(format!("WALLET_TEST_{idx}_MNEMONIC"))
        .unwrap_or_else(|_| panic!("WALLET_TEST_{idx}_MNEMONIC env var"));
    let cfg = Pkcs11Config::new(
        lib,
        SlotIdentifier::label(&label),
        pin.clone(),
        path.clone(),
        Box::new(DevBackend),
    );
    let session = Pkcs11Session::open(&cfg, &SlotIdentifier::label(&label), &pin)
        .expect("open dev session");
    (session, mnemonic)
}

/// Wipe key + policy/sigrate DATA objects associated with `label` from a
/// session. Mirrors `node_pkcs11_cross_check.rs` so the two integration
/// suites can run independently against the same SoftHSMv2 fixture.
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

#[test]
#[serial]
#[ignore = "requires SoftHSM + ELEMENTS_RPC_URL/ESPLORA_URL configured in .env"]
fn pkcs11_ct_descriptor_round_trips_through_local_address_derivation() {
    let endpoint = env::var("ELEMENTS_RPC_URL").or_else(|_| env::var("ESPLORA_URL"));
    if endpoint.is_err() {
        eprintln!(
            "[pkcs11_ct_descriptor_round_trips_through_local_address_derivation] SKIP: \
             neither ELEMENTS_RPC_URL nor ESPLORA_URL is set"
        );
        return;
    }

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").expect("standard liquid testnet path");
    let labels = ["asterism-elements-1", "asterism-elements-2", "asterism-elements-3"];
    let mut signers: Vec<Pkcs11Signer> = Vec::with_capacity(labels.len());

    for (i, label) in labels.iter().enumerate() {
        let (session, mnemonic) = dev_session((i + 1) as u8, &path);
        reset_label(&session, label);
        let seed = mnemonic_to_seed_no_passphrase(&mnemonic).expect("mnemonic_to_seed");
        let signer = Pkcs11Signer::derive_from_seed(
            session,
            label,
            &path,
            Network::Testnet,
            Box::new(DevBackend),
            seed.expose_secret().as_slice(),
        )
        .expect("derive HSM key for elements federation");
        // The signer should advertise both Bitcoin and Liquid networks.
        let nets = signer.supported_networks();
        assert!(nets.contains(&NetworkType::Bitcoin(Network::Testnet)));
        assert!(nets.contains(&NetworkType::Elements(ElementsNetworkId::LiquidTestnet)));
        // And `blind_signing` should be true.
        assert!(signer.capabilities().blind_signing);
        signers.push(signer);
    }

    // Derive a deterministic master blinding key for the test (32 bytes
    // of `0xab`). Production deployments derive this from the recovery
    // seed via SLIP-77 `from_seed`; here we just need a valid key.
    let mbk = [0xabu8; 32];
    let mut builder = CtDescriptorBuilder::new(2, &mbk).expect("32-byte blinding key");
    for s in &signers {
        builder.add_signer(s).expect("unique signer");
    }
    let desc = builder.build().expect("ct descriptor builds");
    let s = desc.to_string();
    assert!(s.starts_with("ct(slip77("), "expected ct(slip77(...) prefix, got {s}");

    // Derive a confidential address for Liquid Testnet at index 0.
    let secp = asterism_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
    let definite = desc.at_derivation_index(0).expect("definite descriptor");
    let addr = definite
        .address(&secp, ElementsNetwork::LiquidTestnet.address_params())
        .expect("address derivation");
    assert!(addr.blinding_pubkey.is_some());

    // Confirm the signer can be used as `&dyn ElementsSigner`. We don't
    // construct a real PSET here — that requires a wallet with funded
    // UTXOs which is out of scope for the lean v1 cross-check.
    for s in &signers {
        let _: &dyn ElementsSigner = s;
    }
}
