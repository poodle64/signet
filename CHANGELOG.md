# Changelog

All notable changes to signet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to calendar-based versioning (YYYY.M.x).

## [2026.7.1] - 2026-07-10

### Added

- `headers` subcommand — the vend-to-headers helper for Claude Code's `.mcp.json` `headersHelper` contract. Performs a fresh attestation each run (deliberately no bearer-cache reuse: always-fresh proof of possession, matching `verify`) followed by `verify`'s credential-vend leg: it attests to a broker (`--broker`), vends a named credential (`--credential`), and prints ONE compact-JSON header line to stdout — `{"Authorization":"Bearer <value>"}` by default, or `{"<name>":"<value>"}` with `--header <name>` and `--format raw`. The credential must resolve to `static` material with exactly one field; anything else (a `session` credential, or zero/multiple static fields) is a typed refusal, never a partial print. Exit codes extend `verify`'s vocabulary: 0 success, 2 key missing, 3 attestation rejected, 4 credential out of scope, 5 credential not found, 6 unusable material. Like `verify`, its output never contains the minted bearer, and on failure it never contains the credential value.

## [2026.7.0] - 2026-07-04

### Added

- `verify` subcommand — consumer pre-flight with typed exit codes. Runs the attestation round-trip against a broker (`--broker`) and optionally probes a credential vend (`--credential`), then exits 0 (success), 2 (no key enrolled), 3 (attestation rejected), 4 (credential out of vend scope), or 5 (credential not in the catalogue), so callers branch on the exact failure mode instead of one opaque "unauthorised". Its output never contains the minted bearer or a credential value.
- `doctor --backend <name>` probes a single backend instead of all three, and an unknown backend name is now rejected instead of silently ignored.
- Branding: `docs/branding/` carries the monochrome signet-ring wordmark and monogram (single ink `#111111`, geometry-only marks, monospace wordmark) with a canonical-colour reference; the README header now uses the wordmark.
- CI test gate (`.github/workflows/ci.yaml`): gofmt, go vet, and the full test suite run on every pull request and push to main, natively on both release platforms.

### Changed

- **Repository layout**: the flat root package is now the standard Go CLI shape — `cmd/signet/` plus `internal/signer` (backends), `internal/attest` (broker client, bearer cache, auth/verify), `internal/agent` (daemon and socket client), and `internal/datadir`. The Swift Secure-Enclave shim lives at `internal/signer/enclave.swift` and its build products stay inside that package directory. Build and install interfaces are unchanged (`make build`, `make test`, same release artifacts).
- CLI polish: `version` no longer doubles the `go` prefix (`(go1.25.10)`, not `(go go1.25.10)`); `-h`/`--help` on a subcommand exits 0 after printing the flag list instead of exit 1 with `error: flag: help requested`; missing-argument errors share one shape (`signet <subcommand>: a <thing> argument is required`); `verify` transport errors are reported once, not twice; help-text columns align and the `82..95` slot range is labelled as hex.
- Broker rejections are classified by a typed error carrying the HTTP status instead of matching on message text (no wire or exit-code change).
- Release workflow: failure notifications post directly to ntfy (the private composite action can never resolve on this public repo), and `actions/checkout` is pinned at v7.0.0.
- Documentation truth-up: the bearer cache is keyed by broker URL plus the enrolled key's fingerprint (not an identity name); configuration is flags-only with no environment variables; the `agent` daemon is documented as the deliberate long-lived counterpart to the single-shot credential-helper flows; usage now covers all seven subcommands.

### Fixed

- Homebrew formula `test do` block asserted behaviour that no longer exists (no-argument invocation exiting 1 with lowercase `usage` on stderr); it now asserts the real contract — help on stdout exit 0, unknown subcommand exit 1.

## [2026.6.6] - 2026-06-29

### Added

- `agent` subcommand — an own-the-token, sign-on-request daemon for workloads that cannot reach the hardware directly (a container with no pcscd socket / no path to the YubiKey). One process owns the single-access token and serves a Unix socket per `--bind <socket>=<slot>`; each socket is pinned to one slot, so a client can only ever sign with that socket's key (the slot is never taken from a request). Hardware access is serialised across bindings; the agent answers only "return the public key" and "sign", and never generates or overwrites a key. The `ssh-agent` / SPIRE node-agent / HSM-proxy pattern.
- `--agent <socket>` flag on `sign`, `enrol`, and `auth` — forwards signing and public-key reads to a running agent instead of opening local hardware. Attestation is resolve-by-public-key, so the broker is unaffected by how the signature was produced. (poodle64/signet#3)

## [2026.6.5] - 2026-06-28

### Added

- `version` subcommand — prints the signet version, platform, and Go runtime.
- `doctor` subcommand — preflight check of the signing environment (backend availability and hardware reachability), with platform-specific probes.
- `help` subcommand and `-h` / `--help` — usage for every subcommand.

### Changed

- Documentation truthed-up to a finished-product state (README, usage, configuration, and backends guides); added CONTRIBUTING.md and SECURITY.md.

## [2026.6.4] - 2026-06-25

### Changed

- **The CLI is flag-driven; the `SIGNET_BACKEND`, `SIGNET_PIV_SLOT`, and `SIGNET_IDENTITY` environment variables are removed.** Backend, PIV slot, and Secure-Enclave identity are now selected by `--backend`, `--slot`, and `--identity`, accepted on every subcommand — e.g. `signet auth --backend piv --slot 9a <broker-url>`. **Breaking:** callers that configured signet through the environment must pass the equivalent flags (an embedding consumer passes them per invocation). `--backend` still falls back to platform auto-detect when omitted; `--slot` defaults to `9c`; `--identity` defaults to `consumer`. Explicit per-invocation selection is self-documenting and removes the ambient-environment footgun — a single exported `SIGNET_PIV_SLOT` would have forced every consumer on a host onto one slot, hence one identity.

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

First public release. signet was split out of the broker's repository into its own standalone repository and published. This is the first release installable without repository access.

### Added

- Cross-platform hardware-rooted signing CLI in a single self-contained Go binary, with three backends compiled in and selected at runtime — TPM 2.0 (pure Go, `go-tpm`), YubiKey/PIV slot 9c (`go-piv`, cgo/PC-SC), and Apple Secure Enclave (CryptoKit shim linked via cgo). The backend is chosen by `SIGNET_BACKEND` or auto-detected.
- `enrol`, `sign`, and `auth` subcommands. `auth` implements the credential-helper contract (attest → cache → emit an `Authorization` header), compatible with the Claude Code `headersHelper` and the same shape as `git`/`docker`/AWS `credential_process` helpers.
- Secure Enclave backend that works on an **unsigned** binary via CryptoKit's self-stored-key-blob model — the Enclave's wrapped key blob is stored in a file, the keychain is never touched, and no code-signing entitlement or notarisation is required.
- A bearer cache keyed by broker URL **and** identity, renewing as the token ages.
- Homebrew formula and a nix (`fetchurl` + SRI) derivation for installing the per-platform release binary.
- A per-platform release workflow (darwin/arm64, linux/amd64).
