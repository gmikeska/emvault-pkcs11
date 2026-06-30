//! Quick address generation from the 3-of-5 dev federation.
//! Run: cargo test -p emvault-pkcs11 --features "integration elements" --test gen_address -- --nocapture

#![cfg(all(feature = "integration", feature = "elements"))]

use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use emvault_core::Signer;
use emvault_dev_signer::DevBackend;
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
fn generate_federation_addresses() {
    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let labels = [
        "fed-addr-1",
        "fed-addr-2",
        "fed-addr-3",
        "fed-addr-4",
        "fed-addr-5",
    ];

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

    // Deterministic SLIP-77 master blinding key for dev federation
    let mbk = [0x42; 32];
    let mut builder = CtDescriptorBuilder::new(3, &mbk).expect("builder");
    builder = builder.key_mode(emvault_elements::descriptor::CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s).expect("add signer");
    }
    let ct_desc = builder.build().expect("ct descriptor");

    eprintln!("\n=== 3-of-5 Federation Confidential Descriptor ===");
    eprintln!("{ct_desc}\n");

    let secp = emvault_elements::elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
    let network = ElementsNetwork::ElementsRegtest;

    eprintln!("=== Receive Addresses (Elements Regtest) ===");
    for idx in 0..5u32 {
        let definite = ct_desc.at_derivation_index(idx).expect("definite");
        let addr = definite
            .address(&secp, network.address_params())
            .expect("address");
        eprintln!("[{idx}] {addr}");
    }
    eprintln!();

    // Also print signer xpubs for reference
    eprintln!("=== Signer XPubs ===");
    for (i, s) in signers.iter().enumerate() {
        eprintln!("[{}] fp={} xpub={}", i + 1, s.fingerprint(), s.xpub());
    }
}
