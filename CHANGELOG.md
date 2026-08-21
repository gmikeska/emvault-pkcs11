# Changelog

All notable changes to `emvault-pkcs11` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

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
