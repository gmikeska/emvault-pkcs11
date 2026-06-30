//! Derive the SLIP-77 blinding private key for the federation's receive address.
//! Run: cargo test -p emvault-pkcs11 --features "integration elements" --test derive_blinding -- --nocapture

#![cfg(all(feature = "integration", feature = "elements"))]

use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use emvault_core::Signer;
use emvault_dev_signer::DevBackend;
use emvault_elements::descriptor::CtKeyMode;
use emvault_elements::{CtDescriptorBuilder, ElementsNetwork};
use emvault_pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};

fn load_env() {
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("emvault-core/.env");
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
        let l = format!("emvault/v1/{label}/{suffix}");
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
fn print_blinding_key_for_address_0() {
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let labels = ["fed-bk-1", "fed-bk-2", "fed-bk-3", "fed-bk-4", "fed-bk-5"];

    let signers: Vec<Pkcs11Signer> = labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let idx = u8::try_from(i + 1).expect("fits");
            let session = dev_session(idx, &path);
            reset_label(&session, label);
            Pkcs11Signer::derive_from_seed(
                session,
                label,
                &path,
                Network::Testnet,
                Box::new(DevBackend),
                &[],
            )
            .expect("derive HSM key")
        })
        .collect();

    let mbk = [0x42; 32];
    let mut builder = CtDescriptorBuilder::new(3, &mbk).expect("builder");
    builder = builder.key_mode(CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s).expect("add signer");
    }
    let ct_desc = builder.build().expect("ct descriptor");

    let secp = emvault_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
    let network = ElementsNetwork::ElementsRegtest;

    // Derive the definite descriptor at index 0
    let definite = ct_desc.at_derivation_index(0).expect("definite");
    let addr = definite
        .address(&secp, network.address_params())
        .expect("address");

    eprintln!("\nConfidential address [0]: {addr}");

    // Extract the blinding pubkey from the address
    let blinding_pk = addr.blinding_pubkey.expect("has blinding pubkey");
    eprintln!("Blinding pubkey: {}", blinding_pk);

    // Use the library's own Slip77 type to derive the blinding private key
    use emvault_elements::elements_miniscript::slip77::MasterBlindingKey;

    let slip77_mbk = MasterBlindingKey::from(mbk);
    let unconf_spk = definite.descriptor.script_pubkey();
    eprintln!("Script pubkey: {unconf_spk}");

    let bk_secret = slip77_mbk.blinding_private_key(&unconf_spk);
    eprintln!(
        "Blinding private key (hex): {}",
        hex::encode(bk_secret.secret_bytes())
    );

    // Verify: derive the public key from the private key and check it matches
    let bk_public = elements::secp256k1_zkp::PublicKey::from_secret_key(&secp, &bk_secret);
    eprintln!("Derived blinding pubkey: {bk_public}");
    assert_eq!(
        bk_public, blinding_pk,
        "derived blinding pubkey must match address blinding pubkey"
    );
    eprintln!("Blinding key verification: PASSED");
}
