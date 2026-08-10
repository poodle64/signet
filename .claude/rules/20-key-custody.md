---
paths:
  - '**/internal/signer/**'
  - '**/internal/agent/**'
  - '**/internal/datadir/**'
  - '**/internal/attest/cache.go'
  - '**/cmd/signet/**'
---

# Signet Key Custody

A non-exportable signing key sealed in secure hardware is signet's entire reason to exist: nothing on disk, in an env var, or in a config file for a stolen laptop image or a leaked `.env` to give away. These invariants govern how that key is **born, held, and never degraded** — going beyond `core/secret-handling.md` (no secret VALUES in a transcript) and `core/supply-chain.md`, which do not cover it.

## 1. Hardware-born, non-exportable

The key is generated inside secure hardware and never leaves it: the SE returns an opaque, hardware-wrapped blob and the private scalar never enters process memory (`Enrol`, `internal/signer/enclave_darwin.go`); TPM and PIV keep it at a fixed handle / on the token. signet moves only the **public** half (SPKI DER, base64, via `marshalSPKI`) and signatures. The agent extends the same guarantee across a socket — pubkey/sign ops only (`internal/agent/server.go`).

- Must NOT add code that exports, serialises, copies, or logs the private key; only the public key and a signature leave a backend, and no code path may hold the private key in a file, env var, log, or argv.

## 2. No software-key fallback, ever

`New` and `autoDetect` (`internal/signer/signer.go`) resolve to exactly one hardware backend or return an error — there is deliberately no software path. A single software-fallback branch silently turns "this identity is hardware-rooted" from always-true into sometimes-true on the one host that took the fallback.

- Must NOT add a software-, file-, or in-memory-key backend, or a "degraded mode" that signs without secure hardware. Absent hardware is a hard failure by design; backend selection resolves to a hardware backend or an error, never a software signer.

## 3. The only permitted on-disk state

Exactly two files, no third: the short-lived **bearer cache** under `~/.signet/cache/` (mode 0600, atomic write, keyed by broker URL **and** the enrolled key's fingerprint — 16 hex of SHA-256(SPKI DER); `internal/attest/cache.go`), and on macOS the **opaque Secure-Enclave blob** at `~/.signet/se-<identity>.key` (mode 0600 under a 0700 dir; `blobPath`/`writeKeyBlob`, `internal/signer/enclave_darwin.go`), which is machine-bound and useless if copied. TPM and PIV write no key file. Deleting the cache simply forces a re-attest.

- Must NOT add an on-disk artefact holding secret material beyond these two. Must keep both at mode 0600 under a 0700 directory, and the cache keyed by broker URL AND the enrolled key's fingerprint, so re-enrolling a new key never serves a bearer minted for the old one.

## 4. The macOS backend stays keychain-free

The SE backend stores its wrapped blob in a file signet owns and never touches the keychain (`internal/signer/enclave_darwin.go`). Persisting an SE key reference in the keychain needs the `com.apple.application-identifier` entitlement (an Apple-team signature) and fails on an unsigned binary with `-34018 errSecMissingEntitlement`; the self-stored-blob path needs neither, so signet runs on the unsigned, ad-hoc binaries `make build` produces.

- Must NOT migrate the SE backend to keychain-backed storage; keep the self-stored-blob model.

## 5. Enrolment is operator-mediated, not trust-on-first-use

`signet enrol` prints the public key (`cmd/signet/main.go`) and the operator pastes it into the broker; signet never auto-registers on first contact. `Enrol` is idempotent and non-destructive — an existing key is read and returned, never clobbered — so re-running cannot silently mint a second identity. The agent has no enrol op; `enrol --agent` only reads the slot's existing public key.

- Must keep `enrol` print-only and non-destructive; must NOT add auto-registration with the broker or trust-on-first-use.

## See also

- `15-attest-boundary.md`: the broker contract this hardware proof feeds.
