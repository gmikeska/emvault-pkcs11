//! Vendor-neutral multisig **fleet** management.
//!
//! A *fleet* is the set of cosigners that together form a federation. Each
//! cosigner is a session target (`library + slot + pin`) + a derivation path +
//! a **backend** — and because the backend is a `Box<dyn HsmBackend>`, a single
//! fleet can **mix vendors**: Securosys `CloudHSM` partitions, the dev SoftHSM
//! shim, and any future HSM, all in one `Vec`.
//!
//! `emvault-pkcs11` stays vendor-neutral, so it cannot construct a
//! `SecurosysBackend` / `DevBackend` itself (that would be a dependency cycle).
//! Vendors plug in through a [`BackendRegistry`] — a `vendor tag → backend
//! factory` map each vendor crate contributes to. [`Fleet::from_env`] reads an
//! `EMVAULT_FLEET_*` description and uses the registry to mint the right backend
//! per member.
//!
//! ## `EMVAULT_FLEET_*` environment schema
//! Fleet-wide:
//! - `EMVAULT_FLEET_NETWORK` — `bitcoin` | `testnet` | `signet` | `regtest`
//!   (default `testnet`).
//!
//! Per member, indexed from `0` (parsing stops at the first missing
//! `_<i>_VENDOR`):
//! - `EMVAULT_FLEET_<i>_VENDOR` — registry tag, e.g. `securosys` / `dev`.
//! - `EMVAULT_FLEET_<i>_LABEL`  — EmVault key label for this cosigner.
//! - `EMVAULT_FLEET_<i>_LIB`    — path to the vendor's PKCS#11 `.so`.
//! - `EMVAULT_FLEET_<i>_SLOT`   — token label (or `_SLOT_ID` for a numeric slot).
//! - `EMVAULT_FLEET_<i>_PIN`    — PKCS#11 user PIN.
//! - `EMVAULT_FLEET_<i>_PATH`   — BIP-32 derivation path (`m/48'/1'/0'/0'`).
//! - `EMVAULT_FLEET_<i>_KEY`    — key init: `shim` (backend-supplied seed,
//!   the default), `seed:<hex>` (derive from this seed), or `load` (load an
//!   already-provisioned key by label).
//!
//! ## Degenerate-fleet guard
//! [`Fleet::validate`] rejects two cosigners that resolve to the **same** key
//! (same vendor + library + slot + path) — a silently-broken 1-key "multisig".
//! Distinctness must come from the token/partition or the path.

use std::collections::HashMap;
use std::path::PathBuf;

use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use secrecy::{ExposeSecret, SecretString};

use crate::backend::HsmBackend;
use crate::config::SlotIdentifier;
use crate::{Pkcs11Config, Pkcs11Error, Pkcs11Session, Pkcs11Signer};

/// How a fleet member obtains its key on the token.
pub enum KeyInit {
    /// Derive a fresh master from this seed. An **empty** seed means "the
    /// backend supplies the seed" (the dev shim's per-slot convention).
    DeriveFromSeed(Vec<u8>),
    /// Load an already-provisioned key by label (a prior ceremony).
    Load,
}

/// Mints fresh `Box<dyn HsmBackend>` instances for one member. Session-open and
/// key derivation each need their own instance, so this is a factory, not a
/// single box.
pub type BackendFactory = Box<dyn Fn() -> Box<dyn HsmBackend> + Send + Sync>;

/// Env-parsed member fields, handed to a [`BackendRegistrar`] so it can build a
/// vendor-specific [`BackendFactory`] (e.g. capturing the library path).
pub struct MemberEnv {
    /// Registry tag (e.g. `securosys`, `dev`).
    pub vendor: String,
    /// EmVault key label.
    pub label: String,
    /// Path to the vendor's PKCS#11 `.so`.
    pub library_path: PathBuf,
    /// Token/partition selector.
    pub slot: SlotIdentifier,
    /// PKCS#11 user PIN.
    pub pin: SecretString,
    /// BIP-32 derivation path.
    pub derivation_path: DerivationPath,
    /// Fleet-wide network.
    pub network: Network,
    /// Key-init strategy.
    pub key_init: KeyInit,
}

/// Builds a [`BackendFactory`] for a parsed member of a given vendor.
///
/// # Errors
/// Vendor-specific validation may reject a member via [`Pkcs11Error`].
pub type BackendRegistrar =
    Box<dyn Fn(&MemberEnv) -> Result<BackendFactory, Pkcs11Error> + Send + Sync>;

/// `vendor tag → registrar`. Each vendor crate contributes its registrar; the
/// fleet looks the tag up from `EMVAULT_FLEET_<i>_VENDOR`.
#[derive(Default)]
pub struct BackendRegistry {
    registrars: HashMap<String, BackendRegistrar>,
}

impl BackendRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `vendor`'s backend registrar. Chainable.
    pub fn register(
        &mut self,
        vendor: impl Into<String>,
        registrar: BackendRegistrar,
    ) -> &mut Self {
        self.registrars.insert(vendor.into(), registrar);
        self
    }

    fn get(&self, vendor: &str) -> Option<&BackendRegistrar> {
        self.registrars.get(vendor)
    }
}

/// A fully-specified cosigner: session target + path + backend factory + init.
pub struct FleetMember {
    /// Registry tag.
    pub vendor: String,
    /// EmVault key label.
    pub label: String,
    /// Path to the vendor's PKCS#11 `.so`.
    pub library_path: PathBuf,
    /// Token/partition selector.
    pub slot: SlotIdentifier,
    /// PKCS#11 user PIN.
    pub pin: SecretString,
    /// BIP-32 derivation path.
    pub derivation_path: DerivationPath,
    /// Fleet-wide network.
    pub network: Network,
    /// Backend factory (mints one instance per PKCS#11 handle needed).
    pub make_backend: BackendFactory,
    /// Key-init strategy.
    pub key_init: KeyInit,
}

/// Multisig fleet builder.
pub struct Fleet;

impl Fleet {
    /// Reject a **degenerate** fleet: two cosigners resolving to the same key
    /// (same vendor + library + slot + path).
    ///
    /// # Errors
    /// [`Pkcs11Error::InvalidConfig`] naming the two colliding member indices.
    pub fn validate(members: &[FleetMember]) -> Result<(), Pkcs11Error> {
        let id = |m: &FleetMember| {
            format!(
                "{}|{}|{}|{}",
                m.vendor,
                m.library_path.display(),
                m.slot,
                m.derivation_path
            )
        };
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                if id(&members[i]) == id(&members[j]) {
                    return Err(Pkcs11Error::InvalidConfig(format!(
                        "degenerate fleet: cosigners {i} and {j} resolve to the same key"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Open a session and derive/load a signer for each member (validates first).
    ///
    /// # Errors
    /// Any session/derivation failure, or [`Pkcs11Error::InvalidConfig`] for a
    /// degenerate fleet.
    pub fn build_signers(members: Vec<FleetMember>) -> Result<Vec<Pkcs11Signer>, Pkcs11Error> {
        Self::validate(&members)?;
        members.into_iter().map(build_member).collect()
    }

    /// Parse a fleet from `EMVAULT_FLEET_*` env vars, using `registry` to mint
    /// each member's backend. See the module docs for the schema.
    ///
    /// # Errors
    /// [`Pkcs11Error::InvalidConfig`] for a malformed/missing field or an
    /// unregistered vendor.
    pub fn from_env(registry: &BackendRegistry) -> Result<Vec<FleetMember>, Pkcs11Error> {
        let network = parse_network(&env_or("EMVAULT_FLEET_NETWORK", "testnet"))?;
        let mut members = Vec::new();
        let mut i = 0usize;
        while let Some(vendor) = opt(&fkey(i, "VENDOR")) {
            let label = req(i, "LABEL")?;
            let library_path = PathBuf::from(req(i, "LIB")?);
            let slot = parse_slot(i)?;
            let pin = SecretString::from(req(i, "PIN")?);
            let derivation_path = req(i, "PATH")?
                .parse::<DerivationPath>()
                .map_err(|e| Pkcs11Error::InvalidConfig(format!("{}: {e}", fkey(i, "PATH"))))?;
            let key_init =
                parse_key_init(&opt(&fkey(i, "KEY")).unwrap_or_else(|| "shim".into()), i)?;

            let spec = MemberEnv {
                vendor,
                label,
                library_path,
                slot,
                pin,
                derivation_path,
                network,
                key_init,
            };
            let registrar = registry.get(&spec.vendor).ok_or_else(|| {
                Pkcs11Error::InvalidConfig(format!(
                    "no backend registered for vendor '{}'",
                    spec.vendor
                ))
            })?;
            let make_backend = registrar(&spec)?;
            members.push(FleetMember {
                vendor: spec.vendor,
                label: spec.label,
                library_path: spec.library_path,
                slot: spec.slot,
                pin: spec.pin,
                derivation_path: spec.derivation_path,
                network: spec.network,
                make_backend,
                key_init: spec.key_init,
            });
            i += 1;
        }
        if members.is_empty() {
            return Err(Pkcs11Error::InvalidConfig(
                "no EMVAULT_FLEET_0_VENDOR found".into(),
            ));
        }
        Ok(members)
    }
}

fn build_member(m: FleetMember) -> Result<Pkcs11Signer, Pkcs11Error> {
    let pin = m.pin.expose_secret().to_string();
    let cfg = Pkcs11Config::new(
        m.library_path.clone(),
        m.slot.clone(),
        pin.clone(),
        m.derivation_path.clone(),
    );
    let session = Pkcs11Session::open(&cfg, &m.slot, &pin)?;
    match m.key_init {
        KeyInit::DeriveFromSeed(seed) => Pkcs11Signer::derive_from_seed(
            session,
            &m.label,
            &m.derivation_path,
            m.network,
            (m.make_backend)(),
            &seed,
        ),
        KeyInit::Load => Pkcs11Signer::load(
            session,
            &m.label,
            m.derivation_path.clone(),
            m.network,
            (m.make_backend)(),
        ),
    }
}

// --- env helpers ---

fn fkey(i: usize, field: &str) -> String {
    format!("EMVAULT_FLEET_{i}_{field}")
}

fn opt(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn env_or(k: &str, default: &str) -> String {
    opt(k).unwrap_or_else(|| default.to_string())
}

fn req(i: usize, field: &str) -> Result<String, Pkcs11Error> {
    let k = fkey(i, field);
    opt(&k).ok_or_else(|| Pkcs11Error::InvalidConfig(format!("missing {k}")))
}

fn parse_slot(i: usize) -> Result<SlotIdentifier, Pkcs11Error> {
    if let Some(label) = opt(&fkey(i, "SLOT")) {
        Ok(SlotIdentifier::label(label))
    } else if let Some(id) = opt(&fkey(i, "SLOT_ID")) {
        let n = id
            .parse::<u64>()
            .map_err(|e| Pkcs11Error::InvalidConfig(format!("{}: {e}", fkey(i, "SLOT_ID"))))?;
        Ok(SlotIdentifier::slot_id(n))
    } else {
        Err(Pkcs11Error::InvalidConfig(format!(
            "{}: need _SLOT (label) or _SLOT_ID (numeric)",
            fkey(i, "SLOT")
        )))
    }
}

fn parse_key_init(s: &str, i: usize) -> Result<KeyInit, Pkcs11Error> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("load") {
        return Ok(KeyInit::Load);
    }
    if s.is_empty() || s.eq_ignore_ascii_case("shim") {
        return Ok(KeyInit::DeriveFromSeed(Vec::new()));
    }
    if let Some(hex) = s.strip_prefix("seed:") {
        return Ok(KeyInit::DeriveFromSeed(decode_hex(hex).map_err(|e| {
            Pkcs11Error::InvalidConfig(format!("{} seed hex: {e}", fkey(i, "KEY")))
        })?));
    }
    Err(Pkcs11Error::InvalidConfig(format!(
        "{}: expected 'shim', 'load', or 'seed:<hex>'",
        fkey(i, "KEY")
    )))
}

fn parse_network(s: &str) -> Result<Network, Pkcs11Error> {
    match s.trim().to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(Pkcs11Error::InvalidConfig(format!(
            "unknown network '{other}' (bitcoin|testnet|signet|regtest)"
        ))),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|k| u8::from_str_radix(&s[k..k + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(vendor: &str, slot: &str, path: &str) -> FleetMember {
        FleetMember {
            vendor: vendor.into(),
            label: "l".into(),
            library_path: PathBuf::from("/lib.so"),
            slot: SlotIdentifier::label(slot),
            pin: SecretString::from("pin"),
            derivation_path: path.parse().unwrap(),
            network: Network::Testnet,
            make_backend: Box::new(|| unreachable!("not built in validate tests")),
            key_init: KeyInit::DeriveFromSeed(Vec::new()),
        }
    }

    #[test]
    fn distinct_members_validate() {
        let fleet = vec![
            member("securosys", "P1", "m/48'/1'/0'/0'"),
            member("dev", "core-test-1", "m/48'/1'/0'/0'"),
            member("securosys", "P1", "m/48'/1'/0'/1'"),
        ];
        assert!(Fleet::validate(&fleet).is_ok());
    }

    #[test]
    fn same_vendor_slot_path_is_degenerate() {
        let fleet = vec![
            member("securosys", "P1", "m/48'/1'/0'/0'"),
            member("securosys", "P1", "m/48'/1'/0'/0'"),
        ];
        assert!(Fleet::validate(&fleet).is_err());
    }

    #[test]
    fn parse_key_init_variants() {
        assert!(matches!(
            parse_key_init("shim", 0).unwrap(),
            KeyInit::DeriveFromSeed(v) if v.is_empty()
        ));
        assert!(matches!(parse_key_init("load", 0).unwrap(), KeyInit::Load));
        assert!(matches!(
            parse_key_init("seed:00ff", 0).unwrap(),
            KeyInit::DeriveFromSeed(v) if v == vec![0x00, 0xff]
        ));
        assert!(parse_key_init("nonsense", 0).is_err());
    }
}
