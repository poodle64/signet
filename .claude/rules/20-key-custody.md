---
paths:
  - '**/*'
---

# Signet Key Custody

A non-exportable signing key sealed in secure hardware is signet's entire reason to exist: there is nothing on disk, in an env var, or in a config file for a stolen laptop image or a leaked `.env` to give away. The invariants below protect that one guarantee. They go beyond the universal secret-handling rules (`core/21-secret-handling.md`, which forbid reading secret VALUES into a transcript) and the supply-chain rules in `security/`: this rule governs how signet's signing key is **born, held, and never degraded**, which those rules do not cover.

## 1. The signing key is hardware-born and non-exportable

The signing key is generated inside secure hardware and never leaves it. On macOS the Secure Enclave returns an opaque, hardware-wrapped blob and the private scalar never enters process memory (`signer_darwin.go:99-136`); TPM and PIV keep the key at a fixed handle / on the token. signet only ever moves the **public** half (SPKI DER, base64, via `marshalSPKI`, `signer_darwin.go:201-215`) and signatures. The private key must never be written to a file, an env var, a log, or argv, because no code path is allowed to hold it in the first place.

- Must NOT add any code that exports, serialises, copies, or logs the private signing key; the only artefacts that leave the backend are the public key and a signature.

## 2. No software-key fallback, ever

A host with no secure hardware fails loudly; it never degrades to a key on disk. `newSigner` (`signer.go:43-61`) and `autoDetectBackend` (`signer.go:64-79`) resolve to exactly one of the three hardware backends or return an error; there is deliberately no software path. This is the difference between "this identity is hardware-rooted" being **always true** and being **sometimes true**: a single software-fallback branch silently turns the guarantee into a lie on the one host that took the fallback.

- Must NOT add a software-key, file-key, or in-memory-key backend, nor a "degraded mode" that signs without secure hardware. Absent hardware is a hard failure, by design.
- Must keep backend selection resolving to a hardware backend or an error; never to a software signer.

## 3. The only permitted on-disk state

signet persists exactly two kinds of file, and no third is permitted:

1. the short-lived **bearer cache** under `~/.signet/cache/` (mode 0600, atomic write, keyed by broker URL **and** identity; `attest.go:80-130`); deleting it simply forces a re-attest, and
2. on macOS, the **opaque Secure-Enclave key blob** at `~/.signet/se-<identity>.key` (mode 0600 under a 0700 dir; `signer_darwin.go:77-80`, `signer_darwin.go:219-232`), which is machine-bound and useless if copied to another Mac.

The bearer cache is the only token state signet keeps; there is no long-lived secret on disk. TPM and PIV write no key file at all (the key lives in the hardware).

- Must NOT add a new on-disk artefact that holds secret material; the bearer cache and the opaque SE blob are the complete, deliberate inventory.
- Must keep both at mode 0600 under a 0700 directory and the cache keyed by broker URL AND identity, so re-enrolling a new identity never serves a stale bearer minted for the old one.

## 4. The macOS backend stays keychain-free

The Secure Enclave backend stores its wrapped key blob in a file signet owns and never touches the keychain (`signer_darwin.go:3-18`). This is the whole trick: persisting an SE key reference in the keychain needs the `com.apple.application-identifier` entitlement (an Apple-team code signature) and fails on an unsigned binary with `-34018 errSecMissingEntitlement`, whereas the self-stored-blob path needs no entitlement and no code signature. Moving to the keychain would break signet on every unsigned, ad-hoc binary the household builds with `make build`.

- Must NOT migrate the Secure Enclave backend to keychain-backed key storage; keep the self-stored-blob model so signet runs on an unsigned, ad-hoc binary with no entitlement or notarisation.

## 5. Enrolment is operator-mediated, not trust-on-first-use

Enrolment is a deliberate act: `signet enrol` prints the public key (`main.go:61-65`) and the operator pastes it into the broker. signet never auto-registers a new key with the broker on first contact. `Enrol` is idempotent and non-destructive; an existing key is read and returned, never clobbered (`signer_darwin.go:106-122`), so re-running it cannot silently mint a second identity. The broker trusts a public key because the operator enrolled it, not because signet presented it.

- Must keep `enrol` print-only and non-destructive; must NOT add a path where signet registers its public key with the broker automatically or overwrites an existing hardware key.

## Invariants

- Must keep the signing key hardware-born and non-exportable; it must NEVER be written to a file, env var, log, or argv, and no code path may hold the private key.
- Must NOT add a software-key fallback or degraded signing mode; a host without secure hardware fails loudly so "hardware-rooted" is never sometimes-false.
- Must keep the permitted on-disk state to exactly the short-lived bearer cache plus (macOS) the opaque, machine-bound Secure-Enclave blob; must NOT add a third secret-bearing artefact.
- Must keep both at mode 0600 under a 0700 directory and the cache keyed by broker URL AND identity.
- Must keep the macOS backend keychain-free (self-stored-blob model) so it works on an unsigned, ad-hoc binary; the keychain path needs an entitlement and fails -34018.
- Must keep enrolment operator-mediated and `enrol` non-destructive; must NOT add trust-on-first-use or auto-registration.

## See also

- `15-attest-boundary.md`: the broker contract this hardware proof feeds into.
- `00-project-foundations.md`: project scope, architecture, and non-negotiable constraints.
- `core/21-secret-handling.md`: the universal no-secret-in-transcript rule this custody rule sits above.
- `security/`: supply-chain and authentication standards (release pinning, dependency hygiene).
