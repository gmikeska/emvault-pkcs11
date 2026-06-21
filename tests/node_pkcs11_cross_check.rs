//! Cross-validate `Pkcs11Signer`-backed federations against a running
//! Bitcoin Core node via JSON-RPC.
//!
//! Builds a federation from real HSM-resident keys (one per `HSM_DEV_*`
//! token in `.env`) and asks `bitcoind` to derive addresses from the
//! resulting descriptor. Asserts that the node's derivation matches our
//! local derivation bit-for-bit.
//!
//! Gated behind both `integration` (HSM access) and `node-tests` (RPC
//! access). Tests skip gracefully when `bitcoind` is unreachable; HSM
//! presence is required.
//!
//! Run with:
//! ```bash
//! cargo test -p asterism-pkcs11 --features "integration node-tests" \
//!   --test node_pkcs11_cross_check -- --nocapture
//! ```
#![cfg(all(feature = "integration", feature = "node-tests"))]

use std::path::PathBuf;
use std::str::FromStr;

use asterism_core::{Federation, Signer, network::NetworkType};
use asterism_dev_signer::{DevBackend, mnemonic_to_seed_no_passphrase};
use asterism_pkcs11::{Pkcs11Config, Pkcs11Session, Pkcs11Signer, SlotIdentifier, key_ops};
use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use miniscript::{Descriptor, DescriptorPublicKey};
use secrecy::ExposeSecret;
use serial_test::serial;

mod common;

use common::rpc::RpcClient;

// ---------------------------------------------------------------------------
// HSM helpers (mirrors integration.rs; kept inline to avoid cross-crate
// indirection in tests)
// ---------------------------------------------------------------------------

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
/// session. Tests pre-emptively reset to ensure deterministic startup.
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

fn rpc_or_skip(test_name: &str) -> Option<RpcClient> {
    let Some(c) = RpcClient::from_env() else {
        eprintln!("[{test_name}] SKIP: BITCOIN_RPC_* env vars not set");
        return None;
    };
    match c.getblockchaininfo() {
        Ok(info) => {
            let chain = info
                .get("chain")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let ibd = info
                .get("initialblockdownload")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            eprintln!("[{test_name}] connected to {chain} (IBD={ibd})");
            Some(c)
        }
        Err(e) => {
            eprintln!("[{test_name}] SKIP: bitcoind getblockchaininfo failed: {e}");
            None
        }
    }
}

fn local_address_at(
    desc: &Descriptor<DescriptorPublicKey>,
    net: Network,
    idx: u32,
) -> bitcoin::Address {
    desc.at_derivation_index(idx)
        .expect("valid derivation index")
        .address(net)
        .expect("descriptor must produce an address")
}

fn strip_checksum(s: &str) -> &str {
    s.split_once('#').map_or(s, |(d, _)| d)
}

fn assert_descriptors_equivalent(local: &str, remote: &str) {
    let local_no_ck = strip_checksum(local);
    let remote_no_ck = strip_checksum(remote);
    assert_eq!(
        local_no_ck, remote_no_ck,
        "descriptor body should match bit-for-bit\n  local : {local_no_ck}\n  remote: {remote_no_ck}",
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn pkcs11_3of5_descriptor_matches_bitcoin_core() {
    let Some(rpc) = rpc_or_skip("pkcs11_3of5_descriptor_matches_bitcoin_core") else {
        return;
    };

    let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
    let label = "node-cross-3of5";

    // Derive one federation key per dev token from its `WALLET_TEST_{i}`
    // mnemonic and assemble into a 3-of-5 fed.
    let mut signers: Vec<Box<dyn Signer>> = Vec::with_capacity(5);
    for idx in 1..=5u8 {
        let (s, mnemonic) = dev_session(idx, &path);
        reset_label(&s, label);
        let seed = mnemonic_to_seed_no_passphrase(&mnemonic).expect("mnemonic_to_seed");
        let signer = Pkcs11Signer::derive_from_seed(
            s,
            label,
            &path,
            Network::Testnet,
            Box::new(DevBackend),
            seed.expose_secret().as_slice(),
        )
        .expect("derive dev key");
        signers.push(Box::new(signer));
    }

    let fed: Federation =
        Federation::new(3, signers, NetworkType::Bitcoin(Network::Testnet)).unwrap();
    assert_eq!(fed.threshold(), 3);
    assert_eq!(fed.signers().len(), 5);

    let local_desc = fed.descriptor_string().to_string();
    let info = rpc
        .getdescriptorinfo(&local_desc)
        .expect("getdescriptorinfo");
    assert!(!info.isrange, "Fixed-mode pkcs11 federation is non-ranged");
    assert_descriptors_equivalent(&local_desc, &info.descriptor);
    if let Some((_, expected_ck)) = local_desc.split_once('#') {
        assert_eq!(expected_ck, info.checksum, "checksum mismatch");
    }

    let addrs = rpc
        .deriveaddresses(&info.descriptor, None)
        .expect("deriveaddresses");
    assert_eq!(addrs.len(), 1, "Fixed-mode descriptor yields one address");
    let local_addr = local_address_at(fed.descriptor(), Network::Testnet, 0);
    assert_eq!(
        addrs[0],
        local_addr.to_string(),
        "HSM-derived federation address must match bitcoind's derivation"
    );
    assert!(
        addrs[0].starts_with("tb1q"),
        "expected testnet P2WSH (tb1q...), got {}",
        addrs[0]
    );
    eprintln!("3-of-5 HSM federation address: {}", addrs[0]);
}
