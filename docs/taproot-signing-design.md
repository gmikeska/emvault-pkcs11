# Taproot signing — design plan

Status: **design** (2026-08-04). Owner: Greg. Drafted by Maggie.

## Goal

Add Taproot (BIP-340 Schnorr) signing to the federation, honoring one hard
constraint: **`emvault-pkcs11` calls the same methods on the HSM-specific crate
regardless of how that crate talks to its hardware.** Securosys signs Schnorr
over **TSB REST** (PKCS#11 has no Schnorr); the dev signer signs in software.
`emvault-pkcs11` must not know or care which.

## The signing abstraction (core of the constraint)

Today signing is **not** in the backend contract: `emvault-pkcs11/src/signer.rs`
computes a P2WSH sighash and calls `ecdsa::sign_with_low_s(session, handle, …)`
inline — baking in "the mechanism is PKCS#11 ECDSA." Taproot breaks that, so
signing moves onto the backend as two **capability traits** (Greg's "up to two
impls per vendor crate"):

```rust
// emvault-pkcs11::backend  (object-safe, transport-neutral)

/// SegWit v0: ECDSA over a P2WSH sighash (low-S / BIP-146).
pub trait SegwitSigner: Send + Sync {
    fn sign_ecdsa(
        &self,
        session: &Session,
        key: ObjectHandle,
        sighash: &[u8; 32],
    ) -> Result<secp256k1::ecdsa::Signature, HsmBackendError>;
}

/// SegWit v1 (Taproot): BIP-340 Schnorr over a taproot sighash.
/// Script-path multisig ⇒ the cosigner key is untweaked ⇒ no tweak arg.
pub trait TaprootSigner: Send + Sync {
    fn sign_schnorr(
        &self,
        session: &Session,
        key: ObjectHandle,
        sighash: &[u8; 32],
    ) -> Result<secp256k1::schnorr::Signature, HsmBackendError>;
}
```

`HsmBackend` gains two **capability accessors**, defaulting to "unsupported":

```rust
pub trait HsmBackend: Send + Sync + Debug {
    // … existing: backend_name, derive_master_key, derive_path,
    //             read_xpub, master_fingerprint …
    fn segwit_signer(&self)  -> Option<&dyn SegwitSigner>  { None }
    fn taproot_signer(&self) -> Option<&dyn TaprootSigner> { None }
}
```

- `emvault-pkcs11`'s `sign_transaction` inspects each PSBT input: **P2WSH →
  `backend.segwit_signer()`**, **P2TR → `backend.taproot_signer()`**; a `None`
  capability is a clean `SignerError`, never a panic.
- The existing `ecdsa::sign_with_low_s` becomes a **provided `SegwitSigner`**
  (`Pkcs11EcdsaSigner`) any PKCS#11-ECDSA backend can hand back from
  `segwit_signer()` — so dev + Securosys ECDSA keep working unchanged.
- `capabilities.taproot = backend.taproot_signer().is_some()` — fixes the
  current hard-coded `taproot: true` fib.

### Key identity — backend maps handle → its own ref (Greg's decision #2)

The signer keeps passing the PKCS#11 `ObjectHandle` from `derive_path`. The
Securosys `TaprootSigner` internally reads the key's `CKA_LABEL` (via the passed
`session`) → the TSB key id → `TsbClient::sign_bip340(label, sighash)`. No
transport-neutral `KeyRef` leaks into the contract.

## Taproot federation key model

**Recommendation: `tr(NUMS_internal, sortedmulti_a(k, <cosigner x-only keys>))`
— script-path taproot multisig via `OP_CHECKSIGADD`.**

- Internal key is an unspendable NUMS point (no key-path spend).
- Each cosigner signs the **script-path** sighash with its **untweaked** leaf
  key → a plain BIP-340 signature. This is why `TaprootSigner::sign_schnorr`
  needs **no tweak argument**, and why Securosys only needs raw BIP-340 from TSB.
- Alternative (key-path MuSig2) is an interactive multi-round protocol — much
  larger, deferred / out of scope.

## Prerequisite: Taproot descriptors in `emvault-core`

`emvault-core` today builds only `wsh(sortedmulti(…))` (`descriptor.rs`). A
Taproot federation can't even be constructed yet. Needs: a taproot `KeyMode`
(or a parallel builder) producing `tr(NUMS, sortedmulti_a(…))`, x-only key
handling, and address derivation. This is the biggest non-signing chunk.

## Phasing

1. **`emvault-pkcs11` — the abstraction.** Add `SegwitSigner` + `TaprootSigner`
   + the two `HsmBackend` accessors + the provided `Pkcs11EcdsaSigner`. Refactor
   `sign_transaction` to route P2WSH through `segwit_signer()` (behavior
   provably unchanged) and P2TR through `taproot_signer()`. Wire
   `capabilities.taproot`. Taproot path returns "unsupported" until backends
   land. Gate: ECDSA regression-clean (existing pkcs11 + multivendor tests).
2. **`emvault-securosys` — TSB Schnorr.** Implement `TsbClient::sign_bip340`
   (POST `/v1/sign`, `signatureType=BIP340`, JWT auth), add TSB config
   (`SECUROSYS_TSB_URL` + JWT source), impl `TaprootSigner` (handle→label→TSB).
   Gate: a **live raw BIP-340 sig on SBX01** verified with `secp256k1`.
3. **`emvault-dev-signer` — software Schnorr.** Add BIP-340 to the dev shim
   (keeps it "in the HSM") or host-side in `DevBackend`; impl `TaprootSigner`.
   Gate: software Schnorr sig verifies.
4. **`emvault-core` — Taproot descriptor.** `tr(NUMS, sortedmulti_a)` builder +
   x-only keys + address derivation. Gate: descriptor round-trips through
   miniscript; addresses match a reference.
5. **`emvault-pkcs11` — P2TR PSBT signing.** `sign_transaction` computes the
   taproot script-path sighash and writes `tap_script_sigs`; finalize a
   script-path witness. Gate: node-free finalize with real Schnorr witnesses.
6. **e2e.** A mixed-vendor taproot federation (dev + Securosys) signs a P2TR
   script-path spend end-to-end. (No automated Securosys test — 90-day sandbox;
   an example, per the SegWit-migration precedent.)

## Decisions (locked 2026-08-04, Greg)

1. **Federation model:** `tr(NUMS, sortedmulti_a)` **script-path** multisig.
2. **ECDSA routing:** move ECDSA **fully** onto the backend — `emvault-pkcs11`
   never signs directly; both algorithms go through the capability traits.
3. **TSB auth:** JWT **refresh flow** (not a static token). Base URL
   `sbx-rest-api.cloudshsm.com`.
4. **Dev Schnorr:** implemented **inside the dev shim** (`libemvault_dev_hsm`) —
   signing stays "in the HSM."
5. **Derivation:** **BIP-86** (`m/86'/…`) for taproot vaults.
6. **Scope:** all the way to a **spendable taproot vault in `test-app-pkcs11`**,
   split into committable phases.

### Trait-capability wiring (resolves the blanket/coherence detail)

Because attribute-based backends get `HsmBackend` via the blanket (they can't
override its methods per-type), the capability accessors are wired as:

- **Provided `Pkcs11EcdsaSigner`** (`const ECDSA: Pkcs11EcdsaSigner`) implements
  `SegwitSigner` via the existing `ecdsa::sign_with_low_s` (`CKM_ECDSA`). Used by
  **both** dev and Securosys — their SegWit signing is identical PKCS#11 ECDSA
  (proven by `securosys_live`).
- **Blanket `impl<T: AttributeDerivation> HsmBackend for T`:**
  `segwit_signer() = Some(&ECDSA)` (every attribute/PKCS#11 backend does ECDSA),
  `taproot_signer() = <T as AttributeDerivation>::taproot_signer(self)`.
- **`AttributeDerivation`** gains one defaulted method
  `fn taproot_signer(&self) -> Option<&dyn TaprootSigner> { None }` so a
  blanket-backed backend (DevBackend) can opt into Taproot.
- **Direct `HsmBackend` impls (Securosys):** provide both accessors themselves
  (`segwit_signer = Some(&ECDSA)`, `taproot_signer = Some(&self.tsb_taproot)`).

## Committable phases

1. **`emvault-pkcs11` signing abstraction + ECDSA fully on the backend.**
   Traits, provided `Pkcs11EcdsaSigner`, accessors + blanket wiring, refactor
   `sign_transaction` to route P2WSH → `segwit_signer()` (behavior unchanged) and
   P2TR → `taproot_signer()` (clean unsupported error until Phase 2/3). Wire
   dev + Securosys `segwit_signer`. Gate: ECDSA regression-clean.
2. **`emvault-securosys` TSB Schnorr.** `TsbClient::sign_bip340` + JWT refresh +
   TSB config; `TaprootSigner` (handle→label→TSB). Gate: live raw BIP-340 on SBX01.
3. **`emvault-dev-signer` software Schnorr.** BIP-340 in the shim; `DevBackend`
   `taproot_signer`. Gate: software Schnorr verifies.
4. **`emvault-core` taproot descriptor.** `tr(NUMS, sortedmulti_a)`, BIP-86,
   x-only keys, address derivation. Gate: miniscript round-trip + address ref.
5. **`emvault-pkcs11` P2TR PSBT signing.** Taproot script-path sighash →
   `tap_script_sigs` → finalize. Gate: node-free finalize with Schnorr witnesses.
6. **`test-app-pkcs11` taproot vault.** BIP-86 fleet path + taproot federation
   option; mixed-vendor spendable-vault example (no automated Securosys test).
