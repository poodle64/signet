# Changelog

All notable changes to signet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to calendar-based versioning (YYYY.M.x).

## [2026.6.3] - 2026-06-25

### Added

- PIV (YubiKey) backend: `SIGNET_PIV_SLOT` selects the signing slot per identity — `9a`, `9c`, `9d`, `9e`, or a retired key-management slot `82`–`95`; unset defaults to `9c` (back-compat). Each PIV slot holds an independent keypair and the broker resolves identity by public key, so one YubiKey now roots **multiple distinct identities — one per slot, up to ~24** — instead of only the single slot-9c identity. This is what makes a single token viable for a multi-consumer host: e.g. an admin identity on `9a` enrolled alongside a warming identity on `9c`, each with its own scope. `enrol` provisions the chosen slot's key (default management key) on first use. Validated on a real YubiKey 5: `9c` and `9a` enrol independent, individually-stable keys; the unset default stays `9c`; an invalid slot is rejected. A gated hardware regression test (`TestPIV_HW_MultiSlot_DistinctStableKeys`) guards it.

## [2026.6.2] - 2026-06-25

### Fixed

- PIV (YubiKey) backend: `enrol` now persists and re-reads its slot-9c key correctly. `pivPublicKey` decided whether a key existed by probing the slot's X.509 **certificate** — which `GenerateKey` never writes — so every `enrol` regenerated a fresh key (a different public key each call) and `sign`/`PublicKeyDER` reported an empty slot. It now reads the key directly via go-piv `KeyInfo` (firmware ≥ 5.3.0), falling back to the attestation certificate's key for older firmware. First end-to-end enrol → attest → sign was validated against a real YubiKey 5; the PIV path had no hardware round-trip test before, only software backend-selection tests, which is why this shipped.

### Added

- Hardware round-trip regression test (`signer_piv_hw_test.go`, gated behind `SIGNET_PIV_HW_TEST=1`): asserts two consecutive `enrol` calls return the same SPKI and that a `sign` output verifies against the enrolled public key.

## [2026.6.1] - 2026-06-24

### Changed

- `signet auth` no longer takes an identity-id argument; the form is now `signet auth <broker-url>`. The broker resolves the calling consumer by its enrolled public key (resolve-by-key, the SSH `authorized_keys` model) rather than by a presented id, so a consumer holds no identity id at all. `SIGNET_IDENTITY` still selects which local hardware keypair signs the challenge. This is a breaking change to the `auth` invocation for any consumer that previously passed an id.

### Fixed

- Corrected stale `~/.signet` path references in a packaging comment and a test (the Secure-Enclave key blob lives under the platform data dir, not `~/.signet`).

### Documentation

- Rewrote the README to the household standard and added usage, configuration, backend, and building guides.
- Documented `SIGNET_IDENTITY` as the local keypair selector (the SSH-keyfile model).

## [2026.6.0] - 2026-06-22

First public release. signet was split out of the Portcullis repository into its own standalone repository and published. This is the first release installable without repository access.

### Added

- Cross-platform hardware-rooted signing CLI in a single self-contained Go binary, with three backends compiled in and selected at runtime — TPM 2.0 (pure Go, `go-tpm`), YubiKey/PIV slot 9c (`go-piv`, cgo/PC-SC), and Apple Secure Enclave (CryptoKit shim linked via cgo). The backend is chosen by `SIGNET_BACKEND` or auto-detected.
- `enrol`, `sign`, and `auth` subcommands. `auth` implements the credential-helper contract (attest → cache → emit an `Authorization` header), compatible with the Claude Code `headersHelper` and the same shape as `git`/`docker`/AWS `credential_process` helpers.
- Secure Enclave backend that works on an **unsigned** binary via CryptoKit's self-stored-key-blob model — the Enclave's wrapped key blob is stored in a file, the keychain is never touched, and no code-signing entitlement or notarisation is required.
- A bearer cache keyed by broker URL **and** identity, renewing as the token ages.
- Homebrew formula and a nix (`fetchurl` + SRI) derivation for installing the per-platform release binary.
- A per-platform release workflow (darwin/arm64, linux/amd64).
