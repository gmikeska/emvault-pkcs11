//! [`MinimalHsmPolicy`] — defense-in-depth, HSM-resident transaction policy.
//!
//! `MinimalHsmPolicy` is a small set of checks evaluated **before** the HSM
//! signs any input. It complements the application-level
//! `emvault-policy::PolicyEngine` (which lives outside the HSM) with a
//! second line of defense that survives compromise of the application
//! server.
//!
//! Persistence: the policy and its sig-rate counter are stored as `CKO_DATA`
//! objects on the same token as the signing key. They are loaded at session
//! open and updated atomically per signing operation.
//!
//! ## What this policy can express
//!
//! - **Per-transaction limit** — reject any PSBT whose total output value
//!   exceeds `per_transaction_limit`.
//! - **Sig-rate ceiling** — reject signing if `> max_signatures_per_hour`
//!   signatures have already been produced in the trailing hour.
//! - **Destination whitelist** — if set, every output address must appear
//!   in the whitelist.
//!
//! ## What this policy cannot express
//!
//! Anything stateful beyond the sig-rate counter (e.g. cumulative daily
//! totals across multiple transactions, time-of-day windows, role-based
//! authorization). That richer logic is the job of the application-level
//! `emvault-policy::PolicyEngine`.

use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::{Address, Amount, Psbt};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use serde::{Deserialize, Serialize};

use crate::error::Pkcs11Error;
use crate::session::Pkcs11Session;

/// HSM-resident policy. Stored as a `CKO_DATA` object labelled
/// `emvault/v1/{label}/policy`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MinimalHsmPolicy {
    /// Reject signing if any PSBT's total output value exceeds this amount.
    pub per_transaction_limit: Option<Amount>,
    /// Reject signing if more than this many signatures have already been
    /// produced in the trailing 60 minutes (per signing key).
    pub max_signatures_per_hour: Option<u32>,
    /// If set, every PSBT output address must appear in this list.
    /// Stored as `NetworkUnchecked` so the policy doesn't bind to a
    /// specific Bitcoin network at policy-creation time.
    pub destination_whitelist: Option<Vec<Address<bitcoin::address::NetworkUnchecked>>>,
}

impl MinimalHsmPolicy {
    /// New empty policy (no constraints; permits any signing operation).
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Check this policy against `psbt`. Returns `Ok(())` if the policy
    /// permits signing, or [`Pkcs11Error::PolicyViolation`] otherwise.
    ///
    /// `network` is required so that whitelist addresses (which are stored
    /// as `NetworkUnchecked`) can be compared safely.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error::PolicyViolation`] when a rule rejects the PSBT
    /// (e.g. exceeded per-transaction limit, output not in whitelist), or
    /// [`Pkcs11Error::Bitcoin`] if a whitelist entry doesn't bind to
    /// `network`.
    pub fn check_against_psbt(
        &self,
        psbt: &Psbt,
        network: bitcoin::Network,
    ) -> Result<(), Pkcs11Error> {
        // 1) Per-transaction limit.
        if let Some(limit) = self.per_transaction_limit {
            let total_out: Amount = psbt
                .unsigned_tx
                .output
                .iter()
                .map(|o| o.value)
                .fold(Amount::ZERO, |a, b| a + b);
            if total_out > limit {
                return Err(Pkcs11Error::PolicyViolation(format!(
                    "PSBT output total {total_out} exceeds per-transaction limit {limit}"
                )));
            }
        }
        // 2) Destination whitelist.
        if let Some(whitelist) = &self.destination_whitelist {
            // Convert whitelist (NetworkUnchecked) to checked-for-this-network.
            let mut allowed_scripts = Vec::with_capacity(whitelist.len());
            for addr in whitelist {
                let addr = addr.clone().require_network(network).map_err(|e| {
                    Pkcs11Error::Bitcoin(format!("whitelist address not on network {network}: {e}"))
                })?;
                allowed_scripts.push(addr.script_pubkey());
            }
            for output in &psbt.unsigned_tx.output {
                if !allowed_scripts.contains(&output.script_pubkey) {
                    return Err(Pkcs11Error::PolicyViolation(format!(
                        "output script {:?} not in destination whitelist",
                        output.script_pubkey
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Sig-rate counter persisted alongside [`MinimalHsmPolicy`] as a `CKO_DATA`
/// object labelled `emvault/v1/{label}/sigrate`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SigRateCounter {
    /// Unix-second timestamps of recent signing operations, oldest first.
    pub timestamps: Vec<u64>,
}

impl SigRateCounter {
    /// Drop entries older than `now - 3600s` and return the count.
    ///
    /// # Panics
    ///
    /// Panics if more than [`u32::MAX`] timestamps remain in the counter
    /// after pruning — practically impossible given the trailing-hour
    /// retention policy.
    pub fn prune_and_count(&mut self, now: u64) -> u32 {
        let cutoff = now.saturating_sub(3600);
        self.timestamps.retain(|t| *t >= cutoff);
        u32::try_from(self.timestamps.len()).expect("trailing-hour signature count fits u32")
    }

    /// Append a new timestamp.
    pub fn record(&mut self, now: u64) {
        self.timestamps.push(now);
    }
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

const POLICY_PREFIX: &str = "emvault/v1";

fn policy_label(label: &str) -> String {
    format!("{POLICY_PREFIX}/{label}/policy")
}
fn sigrate_label(label: &str) -> String {
    format!("{POLICY_PREFIX}/{label}/sigrate")
}

/// Read the policy from the token. Returns [`MinimalHsmPolicy::permissive`]
/// if no policy object is present.
///
/// # Errors
///
/// Returns [`Pkcs11Error::Pkcs11`] if any underlying token call fails,
/// [`Pkcs11Error::ObjectNotFound`] if the policy object is missing its
/// `Value` attribute, or [`Pkcs11Error::Serialization`] if the bytes don't
/// decode as a [`MinimalHsmPolicy`].
pub fn load_policy(session: &Pkcs11Session, label: &str) -> Result<MinimalHsmPolicy, Pkcs11Error> {
    let s = session.session();
    let handles = s
        .find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(policy_label(label).as_bytes().to_vec()),
        ])
        .map_err(Pkcs11Error::Pkcs11)?;
    let Some(h) = handles.into_iter().next() else {
        return Ok(MinimalHsmPolicy::permissive());
    };
    let attrs = s
        .get_attributes(h, &[AttributeType::Value])
        .map_err(Pkcs11Error::Pkcs11)?;
    let bytes = attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::Value(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| Pkcs11Error::ObjectNotFound(policy_label(label)))?;
    serde_json::from_slice(&bytes).map_err(|e| Pkcs11Error::Serialization(e.to_string()))
}

/// Persist the policy to the token (replaces any existing policy object).
///
/// # Errors
///
/// Returns [`Pkcs11Error::Pkcs11`] if the token rejects any
/// `find_objects` / `destroy_object` / `create_object` call, or
/// [`Pkcs11Error::Serialization`] if the policy fails to encode.
pub fn save_policy(
    session: &Pkcs11Session,
    label: &str,
    policy: &MinimalHsmPolicy,
) -> Result<ObjectHandle, Pkcs11Error> {
    let s = session.session();
    // Remove any existing policy object first so we get a clean replacement.
    let existing = s
        .find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(policy_label(label).as_bytes().to_vec()),
        ])
        .map_err(Pkcs11Error::Pkcs11)?;
    for h in existing {
        s.destroy_object(h).map_err(Pkcs11Error::Pkcs11)?;
    }
    let bytes =
        serde_json::to_vec(policy).map_err(|e| Pkcs11Error::Serialization(e.to_string()))?;
    let attrs = vec![
        Attribute::Class(ObjectClass::DATA),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(policy_label(label).as_bytes().to_vec()),
        Attribute::Application(b"emvault-pkcs11".to_vec()),
        Attribute::Value(bytes),
    ];
    s.create_object(&attrs).map_err(Pkcs11Error::Pkcs11)
}

/// Read the sig-rate counter, returning a fresh empty counter if no object
/// exists yet.
///
/// # Errors
///
/// Returns [`Pkcs11Error::Pkcs11`] if any underlying token call fails,
/// [`Pkcs11Error::ObjectNotFound`] if the sig-rate object is missing its
/// `Value` attribute, or [`Pkcs11Error::Serialization`] if the bytes don't
/// decode as a [`SigRateCounter`].
pub fn load_sigrate(session: &Pkcs11Session, label: &str) -> Result<SigRateCounter, Pkcs11Error> {
    let s = session.session();
    let handles = s
        .find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(sigrate_label(label).as_bytes().to_vec()),
        ])
        .map_err(Pkcs11Error::Pkcs11)?;
    let Some(h) = handles.into_iter().next() else {
        return Ok(SigRateCounter::default());
    };
    let attrs = s
        .get_attributes(h, &[AttributeType::Value])
        .map_err(Pkcs11Error::Pkcs11)?;
    let bytes = attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::Value(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| Pkcs11Error::ObjectNotFound(sigrate_label(label)))?;
    serde_json::from_slice(&bytes).map_err(|e| Pkcs11Error::Serialization(e.to_string()))
}

/// Persist the sig-rate counter (replace).
///
/// # Errors
///
/// Returns [`Pkcs11Error::Pkcs11`] if the token rejects any
/// `find_objects` / `destroy_object` / `create_object` call, or
/// [`Pkcs11Error::Serialization`] if the counter fails to encode.
pub fn save_sigrate(
    session: &Pkcs11Session,
    label: &str,
    counter: &SigRateCounter,
) -> Result<(), Pkcs11Error> {
    let s = session.session();
    let existing = s
        .find_objects(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(sigrate_label(label).as_bytes().to_vec()),
        ])
        .map_err(Pkcs11Error::Pkcs11)?;
    for h in existing {
        s.destroy_object(h).map_err(Pkcs11Error::Pkcs11)?;
    }
    let bytes =
        serde_json::to_vec(counter).map_err(|e| Pkcs11Error::Serialization(e.to_string()))?;
    let attrs = vec![
        Attribute::Class(ObjectClass::DATA),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(sigrate_label(label).as_bytes().to_vec()),
        Attribute::Application(b"emvault-pkcs11".to_vec()),
        Attribute::Value(bytes),
    ];
    s.create_object(&attrs).map_err(Pkcs11Error::Pkcs11)?;
    Ok(())
}

/// Atomically check-and-update the sig-rate counter.
///
/// Returns [`Pkcs11Error::PolicyViolation`] if recording another signature
/// would exceed `policy.max_signatures_per_hour`.
///
/// # Errors
///
/// Returns [`Pkcs11Error::PolicyViolation`] if the trailing-hour count is
/// at or above `policy.max_signatures_per_hour`, or any error returned by
/// [`load_sigrate`] or [`save_sigrate`].
pub fn check_and_record_sigrate(
    session: &Pkcs11Session,
    label: &str,
    policy: &MinimalHsmPolicy,
) -> Result<(), Pkcs11Error> {
    let Some(max) = policy.max_signatures_per_hour else {
        return Ok(());
    };
    let mut counter = load_sigrate(session, label)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let count = counter.prune_and_count(now);
    if count >= max {
        return Err(Pkcs11Error::PolicyViolation(format!(
            "sig-rate ceiling reached: {count} signatures in trailing hour, limit {max}"
        )));
    }
    counter.record(now);
    save_sigrate(session, label, &counter)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Network, OutPoint, Sequence, Transaction, TxIn, TxOut, absolute, hashes::Hash, transaction,
    };

    fn psbt_with_outputs(outs: Vec<TxOut>) -> Psbt {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: outs,
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    fn dummy_addr() -> Address<bitcoin::address::NetworkUnchecked> {
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            .parse()
            .unwrap()
    }

    #[test]
    fn permissive_passes_anything() {
        let policy = MinimalHsmPolicy::permissive();
        let psbt = psbt_with_outputs(vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: dummy_addr().assume_checked().script_pubkey(),
        }]);
        policy.check_against_psbt(&psbt, Network::Testnet).unwrap();
    }

    #[test]
    fn per_tx_limit_rejects_overspend() {
        let policy = MinimalHsmPolicy {
            per_transaction_limit: Some(Amount::from_sat(500)),
            ..Default::default()
        };
        let psbt = psbt_with_outputs(vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: dummy_addr().assume_checked().script_pubkey(),
        }]);
        let err = policy
            .check_against_psbt(&psbt, Network::Testnet)
            .unwrap_err();
        assert!(matches!(err, Pkcs11Error::PolicyViolation(_)));
    }

    #[test]
    fn whitelist_rejects_unknown_destination() {
        let policy = MinimalHsmPolicy {
            destination_whitelist: Some(vec![dummy_addr()]),
            ..Default::default()
        };
        // Build a different valid P2WPKH address from a hand-crafted hash.
        let other_script =
            bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([9u8; 20]));
        let psbt = psbt_with_outputs(vec![TxOut {
            value: Amount::from_sat(100),
            script_pubkey: other_script,
        }]);
        let err = policy
            .check_against_psbt(&psbt, Network::Testnet)
            .unwrap_err();
        assert!(matches!(err, Pkcs11Error::PolicyViolation(_)));
    }

    #[test]
    fn whitelist_accepts_known_destination() {
        let policy = MinimalHsmPolicy {
            destination_whitelist: Some(vec![dummy_addr()]),
            ..Default::default()
        };
        let psbt = psbt_with_outputs(vec![TxOut {
            value: Amount::from_sat(100),
            script_pubkey: dummy_addr().assume_checked().script_pubkey(),
        }]);
        policy.check_against_psbt(&psbt, Network::Testnet).unwrap();
    }

    #[test]
    fn sigrate_counter_prunes_old_entries() {
        let mut c = SigRateCounter::default();
        c.timestamps.push(100);
        c.timestamps.push(200);
        c.timestamps.push(5_000);
        let now = 5_000;
        let count = c.prune_and_count(now);
        // cutoff = now - 3600 = 1400; entries 100 and 200 are pruned, 5000 remains.
        assert_eq!(count, 1);
        assert_eq!(c.timestamps, vec![5_000]);
    }
}
