# signet

Hardware-rooted signing CLI; one self-contained Go binary that proves _which machine_ you are, using a non-exportable key sealed in whatever secure hardware the host has (Apple Secure Enclave, TPM 2.0, or YubiKey/PIV). It is the machine-identity credential helper for a secrets broker: it signs the broker's `/v1/attest` challenge in hardware and exchanges the proof for a short-lived bearer. signet is broker-agnostic; any service implementing the attest contract can consume it.

Full stack, scope, architecture, and constraints live in `.claude/rules/00-project-foundations.md`; this file carries only the non-obvious build and custody reminders.

## Commands

```bash
make build       # macOS: xcrun swiftc compiles internal/signer/enclave.swift into internal/signer/libsignet_se.a, then CGO_ENABLED=1 go build ./cmd/signet links it; other platforms: just the cgo go build
make test        # CGO_ENABLED=1 go test ./...
make clean
```

Layout: `cmd/signet/` (CLI) + `internal/signer|attest|agent|datadir` (backends, broker client, agent daemon, data dir).

## Key Reminders

- cgo means **per-platform native builds**: the SE and PIV backends cannot be cross-compiled. Plain `go build` on macOS fails to link unless `internal/signer/libsignet_se.a` exists; always `make build`.
- The go-tpm software simulator (test-only) is behind the `tpmsimulator` build tag so its OpenSSL dependency stays out of normal builds.
- No software-key fallback and no key at rest are hard invariants; see `.claude/rules/20-key-custody.md`.

## Sources of Truth

- **Rules**: `.claude/rules/` (core + security via symlink)
- **Broker contract**: the `/v1/attest` HTTP API (any broker implementing it)
- Full project context (stack, scope, sources of truth): `.claude/rules/00-project-foundations.md`
