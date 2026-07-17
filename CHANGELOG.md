# Changelog

All notable changes to signet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to calendar-based versioning (YYYY.M.x).

## [2026.7.3] - 2026-07-17

### Added

- `exec` subcommand — the vend-and-exec helper for consumers that need a broker-vended credential in an **environment variable before a child process starts**, which neither `headers` (an HTTP header) nor `vend-to-file` (a file) can provide: a stdio MCP server reads its credential from its own environment at start-up, and Claude Code's `.mcp.json` has no `envHelper` equivalent to `headersHelper`. Without `exec`, the only option was a secret-shaped environment variable sitting in the calling session — inherited by every child process and readable by anything that can read that process's environment (e.g. `printenv`), the exact leak shape `exec` exists to close (poodle64/master-project#184). Performs the same attestation and credential-vend legs as `headers` and `vend-to-file`, resolves one value out of the material with the same `resolveField` widening `vend-to-file` uses (a single or `--field`-selected static field, or a session's `access_token`), builds the child's environment as the current process environment with `--env-var` set to the vended value (replacing, never duplicating, any pre-existing entry of that name), and replaces the current process with `<command>` via `syscall.Exec` — true process-image replacement, not a forked subprocess: no signet parent is left holding the value in memory, no extra PID sits between Claude Code and the launched server, and the child's stdio and signals pass through untouched, which matters because a stdio MCP server speaks its protocol on file descriptors 0 and 1. Command form is `signet exec [flags] --broker <url> --credential <name> --env-var <NAME> [--field <name>] -- <command> [args...]`; the `--` terminator is required and everything after it is the child's argv, never parsed as a signet flag. Nothing is ever printed to stdout on success (stdout belongs to the child's own protocol from the moment it starts, unlike `headers` and `vend-to-file`, which each print one confirmation line), and the vended value is never placed in argv, so it is never visible to `ps`. Every diagnostic and failure message goes to stderr and never contains the credential value or the minted bearer. Exit codes extend the sibling vocabulary: 0 success (never actually observed — `syscall.Exec` replaces the process), 2 key missing, 3 attestation rejected, 4 credential out of scope, 5 credential not found, 6 unusable material, and a new 7 for command-not-found (`<command>` could not be resolved to an executable via `PATH`). `syscall.Exec` has no Windows equivalent (the standard library's own Windows implementation is a stub that always fails); `exec` still builds there but the launch step fails at runtime, so it is unix-only in practice today.
- `headers --bare` — prints the credential value alone instead of wrapping it in a compact-JSON object, for interpolating into a shell command. `--bare` and `--format` are independent axes and compose: `--format` shapes the VALUE (`bearer` prefixes `Bearer `, `raw` does not), `--bare` shapes the FRAMING (JSON object keyed by `--header`, or the value alone). The four shapes are `{"Authorization":"Bearer <v>"}` (default), `{"Authorization":"<v>"}` (`--format raw`), `Bearer <v>` (`--bare`), and `<v>` (`--bare --format raw`). The JSON default is unchanged and remains the `.mcp.json` `headersHelper` contract, so existing consumers are unaffected. This closes a silent trap: a JSON-wrapped value substituted into `curl -H "Authorization: Bearer $v"` builds a malformed header, and the server rejects it with a 401/403 that is indistinguishable from a stale or revoked credential — a failure that misdiagnosed two live credentials as stale across two sessions. `--header` names the JSON key and so has no meaning under `--bare`; combining them is refused rather than silently ignored. (poodle64/signet#5)
- `signet headers --help` (and `-h`) now prints the subcommand's own reference — usage line, flags, the output shape of every mode with a worked `curl` example, and the exit-code table — instead of only Go's bare auto-generated flag list. The shapes are rendered from the same single source the top-level `signet --help` embeds, so the two cannot drift. (poodle64/signet#5)

### Fixed

- `headers --format raw` was documented as printing "the bare value" in `--help`, in `docs/usage.md`, and in the flag's own description, but it has always emitted `{"Authorization":"<value>"}` — the JSON object, minus only the `Bearer ` prefix. The behaviour is unchanged (it is the pre-existing contract) and is now described accurately wherever it appeared; `--bare` is the flag that actually removes the framing. (poodle64/signet#5)
- `headers --bare` refuses a credential whose value carries a CR, LF, or NUL (exit 6, unusable material) rather than printing it. `--bare` is the only output path with no escaping — the JSON framing escapes such a value and stays on one line — and it exists to be interpolated into a header unquoted, so an embedded CRLF was a header-injection and request-splitting vector, and an embedded newline silently broke the single-line output `--bare` advertises. No HTTP field value may contain these (RFC 9110), so such material cannot become one header value. The refusal names the offending control character and never the value. The default JSON path is deliberately unchanged. (poodle64/signet#5)

## [2026.7.2] - 2026-07-16

### Added

- `vend-to-file` subcommand — the vend-to-file helper for consumers that need a broker-vended credential placed at a file (a `.env`, an `.envrc.local`, a stack secret sink) instead of an HTTP header, without the value ever passing through a shell pipeline, a log, or an LLM transcript. Performs a fresh attestation each run (matching `headers`) followed by the same credential-vend leg, then writes ONE field's value atomically to `<dest>` at mode `0600` by default (`--mode` overrides): a temp file is created in `<dest>`'s own directory, written, fsynced, and chmoded, then renamed over `<dest>` only once every prior step has succeeded — on any failure `<dest>` is left exactly as it was, never created and never partially written. Widens material handling beyond `headers`' single-static-field assumption: a `static` credential with more than one field requires `--field <name>` to disambiguate (an ambiguous credential with no `--field`, or a `--field` naming an absent field, is a typed refusal naming the available field *names*, never a value); a `session` credential always resolves its `access_token` field, and a cookie-only session with no `access_token` is a typed refusal naming the gap. `--print-shape` prints only the credential's `kind` and field names — never a value — and writes no file, for inspecting a credential's shape before choosing `--field`. The only line printed to stdout on success is a non-secret byte-count confirmation; every diagnostic and failure message goes to stderr and never contains the credential value or the minted bearer. Exit codes extend `headers`' vocabulary: 0 success, 2 key missing, 3 attestation rejected, 4 credential out of scope, 5 credential not found, 6 unusable material. (poodle64/portcullis#107)

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
