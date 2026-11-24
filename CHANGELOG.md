# Changelog

All notable changes to `emvault-pkcs11` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

## [0.11.0] - 2026-11-24

Adds a PSET-free signing seam and collapses two copies of the signing core into one.

### Added

- **`Pkcs11Signer::sign_sighash(relative, sighash)`** — sign a 32-byte digest at a path
  relative to the federation key, with no PSET involved. Reachable **without** the
  `elements` feature, so a consumer on a different `elements` version can sign without
  re-parsing a PSET across a version gap.

### Changed

- **One signing implementation, two lock disciplines.** `ElementsSigner::sign_pset`'s
  derive-sign-destroy block moved into `sign_sighash_locked`, which both the trait impl and
  the new public method call. `sign_pset` holds the inner guard across its whole loop
  because `cryptoki::Session` is `!Sync`, so it cannot call the locking `sign_sighash` —
  `std::sync::Mutex` is not reentrant and a second lock would deadlock rather than error.
  Two copies of the block would be two places for low-S normalisation and derived-handle
  cleanup to drift, and the copy inside the feature-gated Elements path is the harder one to
  exercise.
- **`inner_lock` is no longer `#[cfg(feature = "elements")]`.** It was gated by association
  with its first caller but names no `elements` type at all — the guard is over
  `{session, loaded, backend}`. Gating it that way made the byte-oriented signing path
  unreachable without pulling in a second `elements`, which is the coupling the seam exists
  to avoid.

Derived-handle cleanup remains unconditional and runs before `?`, so a signing failure does
not leak a derived session object.

## [0.10.0] - 2026-08-28

### Changed
- Released in lockstep with the suite-wide **0.10.0** (`emvault-core` F1/F4/F2 Taproot signing/verification + config-auth security hardening). No functional changes to this crate; rebuilt against `emvault-core` 0.10.0.

## [0.9.0] - 2026-08-21

### Changed
- Released in lockstep with the suite-wide v0.9.0. No functional changes; adds
  GitHub CI workflows, switches inter-crate dependencies to version-only
  requirements (isolated CI resolves against crates.io), and clears a clippy lint.

## [0.8.0] - 2026-08-16

### Added
- **Taproot (BIP-340) script-path signing.** `Pkcs11Signer` now signs P2TR
  `tr(NUMS, multi_a(...))` inputs: it matches the signer's key in the input's
  `tap_key_origins`, computes the BIP-341 tapscript sighash over all prevouts,
  signs it through the backend's `TaprootSigner`, and inserts the Schnorr
  signature into `tap_script_sigs`. The existing P2WSH/ECDSA path is unchanged.
- Signing moved onto the backend as `SegwitSigner` / `TaprootSigner` capability
  traits; `SignerCapabilities.taproot` is advertised when the backend provides a
  Schnorr signer. `TaprootSigner` carries derivation context (label + full BIP-32
  path) so vendor backends can name the key (e.g. Securosys TSB `signKeyName`).

## [0.7.0] - 2026-08-03

### Changed
- Released in lockstep with the suite-wide v0.7.0 update; no functional changes.
  Picks up the Elements nodeless backends and migration planning through the
  `emvault-elements` dependency (behind the `elements` feature).

## [0.6.0] - 2026-07-29

### Changed
- Released in lockstep with the suite-wide reorg-reconciliation update (v0.6.0).
- Documentation updates.

## [0.5.0] - 2026-07-27

### Changed
- Dependency and lockfile refresh; version realigned across the emvault suite.

## [0.4.0] - 2026-07-22

### Changed
- Release-metadata bump only (no functional changes).

## [0.3.0] - 2026-07-13

### Changed
- Documentation and release-metadata updates only.
