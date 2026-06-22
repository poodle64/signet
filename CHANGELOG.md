# Changelog

All notable changes to signet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to calendar-based versioning (YYYY.M.x).

## [2026.6.0] - 2026-06-22

First public release. signet was split out of the Portcullis repository into its own standalone repository and published. This is the first release installable without repository access.

### Added

- Cross-platform hardware-rooted signing CLI in a single self-contained Go binary, with three backends compiled in and selected at runtime — TPM 2.0 (pure Go, `go-tpm`), YubiKey/PIV slot 9c (`go-piv`, cgo/PC-SC), and Apple Secure Enclave (CryptoKit shim linked via cgo). The backend is chosen by `SIGNET_BACKEND` or auto-detected.
- `enrol`, `sign`, and `auth` subcommands. `auth` implements the credential-helper contract (attest → cache → emit an `Authorization` header), compatible with the Claude Code `headersHelper` and the same shape as `git`/`docker`/AWS `credential_process` helpers.
- Secure Enclave backend that works on an **unsigned** binary via CryptoKit's self-stored-key-blob model — the Enclave's wrapped key blob is stored in a file, the keychain is never touched, and no code-signing entitlement or notarisation is required.
- A bearer cache keyed by broker URL **and** identity, renewing as the token ages.
- Homebrew formula and a nix (`fetchurl` + SRI) derivation for installing the per-platform release binary.
- A per-platform release workflow (darwin/arm64, linux/amd64).
