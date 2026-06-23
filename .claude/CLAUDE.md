# signet

Hardware-rooted signing CLI — one self-contained Go binary that proves _which machine_ you are, using a non-exportable key sealed in whatever secure hardware the host has (Apple Secure Enclave, TPM 2.0, or YubiKey/PIV). It is the machine-identity credential helper for the Portcullis secrets broker: it signs the broker's attestation challenge in hardware and exchanges the proof for a short-lived bearer.

## Stack

- **Language**: Go 1.25, cgo required (the Secure Enclave and PIV backends link C/Swift; TPM is pure Go)
- **Backends** (compiled in, runtime-selected): Secure Enclave (CryptoKit Swift shim, macOS), TPM 2.0 (`go-tpm`), YubiKey/PIV slot 9c (`go-piv`, cgo/PC-SC)
- **Protocol**: Portcullis `/v1/attest` credential-helper flow (challenge → sign → bearer → renew); no broker code is vendored
- **Distribution**: per-platform release binaries via a Homebrew tap and a nix (`fetchurl` + SRI) derivation

## Commands

```bash
make build       # builds ./signet (runs the xcrun swiftc step first on macOS)
make test        # CGO_ENABLED=1 go test ./...
make clean
```

## Key Reminders

- cgo means **per-platform native builds**: the SE and PIV backends cannot be cross-compiled. Plain `go build` on macOS fails to link unless `libsignet_se.a` exists — always `make build`.
- **No software-key fallback, by design.** A host without secure hardware fails loudly rather than degrading to a key on disk; do not add a fallback that would quietly reintroduce an at-rest secret.
- The signing key is **non-exportable** and never appears in a file, env var, or log. signet holds no long-lived secret — only a short-lived bearer cache (keyed by broker URL + identity) and, on macOS, the Enclave's opaque hardware-bound key blob.
- Configuration is `SIGNET_*` (`SIGNET_BACKEND`, `SIGNET_IDENTITY`); the former `PORTCULLIS_*` prefix was removed (a breaking rename — the blob is bound to the hardware, not its filename, so relocating it preserves the identity).
- The go-tpm software simulator (test-only) is behind the `tpmsimulator` build tag so its OpenSSL dependency stays out of normal builds.

## Sources of Truth

- **Rules**: `.claude/rules/` (core + security via symlink)
- **Product definition**: `docs/product/` (P01, P03, P08, P09 — internal, gitignored)
- **Secrets governance**: `docs/master/governance/secrets/` — the attestation flow this client implements
- **Broker contract**: the Portcullis `/v1/attest` HTTP API (the one dependency signet speaks to)
