//! [`Pkcs11Session`] — owns the [`cryptoki::context::Pkcs11`] handle plus an
//! authenticated session against a single slot.
//!
//! `Pkcs11Session` is the entry point for everything else in this crate:
//! [`crate::Pkcs11Signer`] holds a session, [`crate::key_ops`] free functions
//! take a session, and [`crate::policy::MinimalHsmPolicy`] is loaded/saved
//! through a session.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use secrecy::SecretString;

use crate::config::{Pkcs11Config, SlotIdentifier};
use crate::error::Pkcs11Error;

/// An authenticated read-write PKCS#11 session.
///
/// Holds the underlying [`Pkcs11`] context, the resolved [`Slot`], and the
/// open [`Session`]. `Drop` releases the session automatically.
pub struct Pkcs11Session {
    ctx: Pkcs11,
    slot: Slot,
    session: Session,
}

impl Pkcs11Session {
    /// Open an authenticated read-write session against the slot named or
    /// numbered by `slot_identifier`.
    ///
    /// The library at `cfg.library_path` is loaded and initialized via
    /// [`Pkcs11::initialize`] before slot resolution. A read-write session
    /// is opened so signing-side mutations (e.g. updating the
    /// [`crate::policy::MinimalHsmPolicy`] sig-rate counter) succeed.
    pub fn open(
        cfg: &Pkcs11Config,
        slot_identifier: SlotIdentifier,
        user_pin: &str,
    ) -> Result<Self, Pkcs11Error> {
        let ctx = Pkcs11::new(&cfg.library_path).map_err(|e| Pkcs11Error::LibraryLoad {
            path: cfg.library_path.display().to_string(),
            source: e,
        })?;
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => {}
            // PKCS#11 modules are process-global; if the same library has
            // already been initialized (e.g. by another `Pkcs11Session` in
            // this process), reuse it rather than failing.
            Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(Pkcs11Error::Initialize(e)),
        }
        let slot = resolve_slot(&ctx, &slot_identifier)?;
        let session = ctx.open_rw_session(slot)?;
        let pin: AuthPin = SecretString::from(user_pin.to_owned());
        match session.login(UserType::User, Some(&pin)) {
            Ok(()) => {}
            // Login state is per-token, not per-session; another session in
            // this process may already hold the User login. That's a valid
            // state for our purposes — proceed.
            Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => return Err(Pkcs11Error::LoginFailed(e)),
        }
        Ok(Self { ctx, slot, session })
    }

    /// Borrow the underlying PKCS#11 context.
    pub fn context(&self) -> &Pkcs11 {
        &self.ctx
    }

    /// Borrow the resolved slot.
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Borrow the authenticated session.
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Read the token's label (useful for diagnostics and signer naming).
    pub fn token_label(&self) -> Result<String, Pkcs11Error> {
        let info = self.ctx.get_token_info(self.slot)?;
        Ok(info.label().trim().to_string())
    }
}

fn resolve_slot(ctx: &Pkcs11, ident: &SlotIdentifier) -> Result<Slot, Pkcs11Error> {
    let slots = ctx.get_slots_with_token().map_err(Pkcs11Error::Pkcs11)?;
    if slots.is_empty() {
        return Err(Pkcs11Error::SlotNotFound(format!(
            "no slots with tokens (looked for {ident})"
        )));
    }
    match ident {
        SlotIdentifier::Label(label) => {
            for slot in slots {
                let info = ctx.get_token_info(slot).map_err(Pkcs11Error::Pkcs11)?;
                if info.label().trim() == label.trim() {
                    return Ok(slot);
                }
            }
            Err(Pkcs11Error::SlotNotFound(format!("label={label}")))
        }
        SlotIdentifier::SlotId(id) => slots
            .into_iter()
            .find(|s| s.id() == *id)
            .ok_or_else(|| Pkcs11Error::SlotNotFound(format!("slot_id={id}"))),
    }
}
