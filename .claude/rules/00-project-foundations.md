---
paths:
  - '**/*'
---

# signet Project Foundations

## Purpose

signet is a hardware-rooted signing CLI: one self-contained, cross-platform Go binary that proves _which machine_ it runs on by holding a non-exportable P-256 signing identity in secure hardware (Apple Secure Enclave, a TPM, or a YubiKey/PIV token), signing a broker's attestation challenge with it, and exchanging that proof for a short-lived bearer token it caches and hands to consumers. It is the machine-identity client for the Portcullis secrets broker; the same shape as AWS IAM Roles Anywhere, generalised across the three secure-hardware substrates a real fleet actually has and scoped to one broker's vend contract.

## Project Scope

### What This Project Does

- Generates and holds a non-exportable P-256 key in secure hardware and prints its public half (SPKI DER, base64) for one-time enrolment with the broker (`enrol`)
- Signs an arbitrary message in hardware (SHA-256 / ECDSA P-256, IEEE P1363 `r||s`) for testing or bespoke flows (`sign`)
- Runs the credential-helper attestation flow (`auth`): request a challenge, sign it in hardware, exchange the signature for a short-lived bearer, cache it (keyed by broker URL **and** the enrolled key's fingerprint), renew as it ages, and emit an `{"Authorization":"Bearer …"}` header on stdout
- Pre-flights a consumer (`verify`): runs the attestation round-trip (and optionally probes a credential vend) and exits with a typed code per failure mode (0/2/3/4/5)
- Owns the hardware for workloads that cannot reach it (`agent`): one daemon holds the token and serves **pubkey and sign only** over per-slot Unix sockets — the ssh-agent pattern — so a container attests without the token ever being mounted into it; clients select it with `--agent <socket>`
- Compiles in three backends and selects one at runtime: Secure Enclave (macOS), TPM 2.0 (Linux/Windows), YubiKey/PIV (cross-platform); selected by `--backend` flag or OS/hardware auto-detection
- Ships per-platform release binaries installable via a Homebrew tap and a nix (`fetchurl` + SRI) derivation

### What This Project Does NOT Do

- Does NOT contain any broker code; it speaks the Portcullis `/v1/attest` HTTP contract and nothing more (no sidecar, no helper process, no PKCS#11 module)
- Does NOT make any authorisation decision; it proves possession of a hardware key, and every challenge issuance, signature verification, bearer minting, and vend-scope decision is the broker's
- Does NOT fall back to a software key; a host with no secure hardware fails loudly rather than degrading to a key on disk
- Does NOT hold a long-lived secret; the only on-disk state is a short-lived bearer cache and (macOS) the Enclave's opaque hardware-bound key blob
- Does NOT keep the credential-helper flows resident: `auth` (like every subcommand except `agent`) runs once and exits, like `git credential` / `docker-credential-*` / AWS `credential_process`. The one long-lived mode is `agent`, which exists solely to own the hardware for socket clients; it serves pubkey/sign only, never generates a key, and never talks to the broker

## Authority Note

This rule documents project-specific practice and relies on master rules for requirements. Master rules define universal principles; this rule describes how signet implements them. The household secrets architecture signet participates in is governed by `docs/master/governance/secrets/`.

## Project Context

### Technology Stack

- **Language**: Go 1.25; cgo required (the Secure Enclave and PIV backends link C libraries; TPM is pure Go)
- **Backends**: Secure Enclave via a CryptoKit/Swift shim (cgo, macOS), TPM 2.0 via `github.com/google/go-tpm` (pure Go), YubiKey/PIV via `github.com/go-piv/piv-go/v2` (cgo, PC/SC) on a selectable slot (`--slot`; 9a/9c/9d/9e/82..95, default 9c — one identity per slot)
- **Crypto**: P-256 / ECDSA, SHA-256, IEEE P1363 signatures; SPKI DER public keys
- **Protocol**: Portcullis `/v1/attest/{challenge,token,renew}` over HTTP
- **Build/dist**: `make build` (on macOS: `xcrun swiftc` compiles `internal/signer/enclave.swift` into `internal/signer/libsignet_se.a`, then `go build ./cmd/signet` links it via cgo; on other platforms: just the cgo `go build`), Homebrew tap, nix `fetchurl` + SRI derivation, per-platform release workflow
- **Layout**: `cmd/signet/` (CLI dispatch) + `internal/signer/` (backends) + `internal/attest/` (broker client, cache, auth/verify) + `internal/agent/` (daemon + socket client) + `internal/datadir/` (`~/.signet`)

### Architecture

```text
  CLI (enrol | sign | auth | verify | doctor | version)          CLI (agent)
        │                                                             │
        ▼                                                             ▼
  Signer interface  ──selected at runtime──▶  backends          per-slot Unix sockets
        │                     ├─ Secure Enclave (CryptoKit shim,      │ pubkey/sign only,
        │                     │                  cgo, macOS)          │ hardware serialised
        │                     ├─ TPM 2.0        (go-tpm, pure Go)     ▼
        │                     └─ YubiKey/PIV    (go-piv, cgo/PC-SC)  --agent clients
        ▼                            ▲                                (a Signer that dials
  Attestation client ──HTTP──▶ broker /v1/attest/{challenge,token,renew}  the socket)
        │
        ▼
  Bearer cache (file, keyed by broker URL + enrolled-key fingerprint)
```

The CLI, the attestation client, and the agent are written against the small `Signer` interface (enrol / pubkey / sign) and never against a specific backend; the `--agent` client is itself just another `Signer`. Only the Secure Enclave backend sits behind a build tag (it links a macOS-only Swift shim); TPM and PIV compile on every platform.

### Core Philosophy

signet is designed around a **non-exportable key sealed in hardware**: there is nothing on disk, in an env var, or in a config file for a stolen laptop image or a leaked `.env` to give away.

- **One binary, three backends**: switching secure hardware is a one-flag `--backend` change, not a migration; the identity model and broker contract are identical across all three substrates.
- **A thin, honest client, not a framework**: the protocol half (challenge → sign → token → renew) is deliberately small and specific to one broker's contract; that is exactly what a credential helper is. SPIRE, mTLS meshes, and full PKI are heavier answers to a problem a single broker does not have.
- **Nothing exportable, nothing persistent**: the signing key never leaves the hardware; the only persisted state is a short-lived bearer cache and the Enclave's machine-bound key blob, useless if copied off the machine.

## Non-Negotiable Constraints

### Design Constraints

- The signing key must be generated in hardware and be non-exportable; it must never appear in a file, env var, log, or argv
- signet must hold no long-lived secret; the bearer cache holds only short-lived tokens scoped to one broker and one identity, and deleting it simply forces a re-attest
- No software-key fallback: a host without secure hardware must fail rather than degrade to a key on disk, so "this identity is hardware-rooted" is never a claim that is sometimes false
- Enrolment is a deliberate, operator-mediated act (the operator pastes the public key into the broker), not trust-on-first-use
- signet vendors no broker code and makes no authorisation decision; it speaks only the `/v1/attest` contract
- The macOS backend must stay keychain-free (the self-stored blob model), so it works on an unsigned, ad-hoc binary with no code-signing entitlement or notarisation

### Technology Constraints

- Go with cgo; per-platform native builds (the SE and PIV backends cannot be cross-compiled)
- Only the Secure Enclave backend may sit behind a build tag (it links a macOS-only Swift shim); TPM and PIV must compile on every platform, and a build tag must NOT be added that drops a backend from the default build
- Dependencies pinned and `go.sum` committed; release binaries pinned by SRI hash (supply-chain discipline, `.claude/rules/security/`)
- Configuration is per-subcommand flags only (`--backend`, `--slot`, `--identity`, `--agent`); there are no environment variables. Cache and data paths carry the `signet` name prefix (`~/.signet/`; no broker brand coupling)
- Australian English in all prose and documentation

## Sources of Truth

- **Master rules**: `.claude/rules/core/` (via symlink); universal principles
- **Security rules**: `.claude/rules/security/` (via symlink); supply-chain and authentication standards
- **Secrets governance**: `docs/master/governance/secrets/`; the attestation architecture this client participates in
- **Product definition**: `docs/product/` (P01 intent, P03 rationalisation, P08 architecture, P09 decisions; internal, gitignored)
- **Broker contract**: the Portcullis `/v1/attest` HTTP API
- **GitHub Issues**: task tracking and feature planning

## Rule Interpretation Notes

- Security rules apply with full weight: this is a key-custody and machine-identity tool, so the secrets-hygiene, supply-chain, and no-secret-at-rest rules are load-bearing, not advisory.
- Project-specific behavioural rules, if added, are defined in numbered rule files (20+, 50+).
