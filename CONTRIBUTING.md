# Contributing to signet

## Build prerequisites

signet uses cgo, which means the build is always a native, per-platform build driven by `make`. You cannot cross-compile from one OS to another.

### macOS

- Go 1.25
- Xcode command line tools (`xcode-select --install`), so that `xcrun swiftc` is available — the Secure Enclave backend is compiled from `se_swift.swift`, a small CryptoKit shim
- A working C compiler (provided by the Xcode tools)

### Linux

- Go 1.25
- A C compiler (`gcc` or `clang`)
- PC/SC development headers for the PIV backend cgo link: `apt install libpcsclite-dev` on Debian/Ubuntu
- TPM support is pure Go (`go-tpm`) and needs no extra system library

### Windows

- Go 1.25
- A C compiler (MinGW-w64 or MSVC)
- TPM is via TBS (built-in); PIV is via PC/SC (built-in on Windows 8+)

## Build and test

```sh
make build       # compile ./signet (runs the Swift shim step first on macOS)
make test        # CGO_ENABLED=1 go test ./...
make clean       # remove the binary and Swift intermediates
```

Never use a bare `go build` on macOS; `make build` compiles the Swift shim into `libsignet_se.a` first, which the cgo link requires. On Linux and Windows a bare `go build` would work but `make build` is the canonical path on all platforms.

### TPM simulator tests

The TPM backend has tests that run against the go-tpm software simulator. They pull in an OpenSSL dependency and are skipped by default:

```sh
go test -tags tpmsimulator ./...
```

### PIV hardware tests

PIV real-hardware tests are gated behind an environment variable to avoid running against production tokens accidentally:

```sh
SIGNET_PIV_HW_TEST=1 go test ./...
```

## Per-platform native-build constraint

cgo cannot be cross-compiled without a matching target sysroot. Each platform's binary must be built on that platform:

- **darwin/arm64** — built on a Mac (Apple Silicon); the Swift shim step is macOS-only
- **linux/amd64** — built on a Linux/amd64 host

The release workflow mirrors this with one native runner per target. Adding a new platform is a new matrix row in `.github/workflows/release.yaml`.

## Code style

- Standard `gofmt` formatting; the CI gate rejects unformatted code
- Australian English in prose and comments
- No backwards-compatibility shims or deprecated wrappers; breaking changes are documented in `CHANGELOG.md`

## Submitting changes

Open a GitHub Issue before starting significant work, so the approach can be agreed before a PR lands. For small fixes a PR directly is fine. Reference the issue number in the PR description.
