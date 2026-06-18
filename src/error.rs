//! Error types for `asterism-pkcs11`.

use asterism_core::SignerError;

/// All errors raised by `asterism-pkcs11`.
#[derive(Debug, thiserror::Error)]
pub enum Pkcs11Error {
    /// Failed to load the PKCS#11 library at the configured path.
    #[error("failed to load PKCS#11 library at {path}: {source}")]
    LibraryLoad {
        /// Path that failed to load.
        path: String,
        /// Underlying error.
        #[source]
        source: cryptoki::error::Error,
    },
    /// PKCS#11 module initialization failed.
    #[error("PKCS#11 initialize failed: {0}")]
    Initialize(cryptoki::error::Error),
    /// No slot matched the requested identifier.
    #[error("PKCS#11 slot not found: {0}")]
    SlotNotFound(String),
    /// The configured slot exists but the token in it is missing or
    /// uninitialized.
    #[error("PKCS#11 slot {0} has no initialized token")]
    NoToken(String),
    /// Login (CKU_USER) failed.
    #[error("PKCS#11 login failed: {0}")]
    LoginFailed(cryptoki::error::Error),
    /// Generic PKCS#11 error.
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] cryptoki::error::Error),
    /// Required PKCS#11 mechanism is not supported by this library/device.
    #[error("PKCS#11 mechanism {0} not supported by this token")]
    MechanismUnsupported(&'static str),
    /// BIP-32 child derivation is not supported in the active strategy or by
    /// the underlying HSM.
    #[error("BIP-32 derivation unsupported by {strategy}: {reason}")]
    DerivationUnsupported {
        /// Name of the active derivation strategy.
        strategy: &'static str,
        /// Why it failed.
        reason: String,
    },
    /// Failed to find a required HSM-resident object (key, chain code,
    /// metadata, etc.).
    #[error("PKCS#11 object not found: {0}")]
    ObjectNotFound(String),
    /// More than one object matched a query that should have been unique.
    #[error("PKCS#11 found {count} objects matching {query} (expected exactly 1)")]
    Ambiguous {
        /// What was being searched for.
        query: String,
        /// Number of matching objects.
        count: usize,
    },
    /// Invalid configuration value.
    #[error("invalid PKCS#11 configuration: {0}")]
    InvalidConfig(String),
    /// HSM-local policy rejected the requested operation.
    #[error("HSM policy violation: {0}")]
    PolicyViolation(String),
    /// secp256k1 error (e.g. invalid pubkey, invalid signature).
    #[error("secp256k1 error: {0}")]
    Secp256k1(String),
    /// Bitcoin parse / encode error.
    #[error("bitcoin error: {0}")]
    Bitcoin(String),
    /// Serialization / deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Environment variable missing or invalid.
    #[error("environment variable {var} missing or invalid: {reason}")]
    Env {
        /// Variable name.
        var: &'static str,
        /// Why parsing failed.
        reason: String,
    },
    /// Generic backend error.
    #[error("backend error: {0}")]
    Backend(String),
}

impl From<Pkcs11Error> for SignerError {
    fn from(e: Pkcs11Error) -> Self {
        match e {
            Pkcs11Error::PolicyViolation(rule) => SignerError::PolicyViolation {
                id: asterism_core::SignerId::new("pkcs11"),
                rule,
            },
            Pkcs11Error::DerivationUnsupported { strategy, reason } => SignerError::SigningFailed {
                id: asterism_core::SignerId::new("pkcs11"),
                reason: format!("{strategy}: {reason}"),
            },
            other => SignerError::Backend(other.to_string()),
        }
    }
}
