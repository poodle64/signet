<div align="center">

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/) [![Release](https://img.shields.io/github/v/release/poodle64/signet?style=flat-square)](https://github.com/poodle64/signet/releases/latest) [![Licence](https://img.shields.io/badge/Licence-MIT-blue?style=flat-square)](LICENSE)

# Signet

_The key that proves which machine you are; sealed in hardware, exportable to no one._

One self-contained Go binary that holds a non-exportable signing identity in whatever secure hardware a host has, and trades a signed challenge for a short-lived bearer token.

[Installation](#installation) · [Features](#features) · [Documentation](#documentation) · [Contributing](#contributing)

</div>

## Why Signet?

A machine that needs secrets has to prove it is itself before a broker will hand anything over. The robust way to do that is a non-exportable key sealed in hardware: the machine signs a challenge, the broker verifies the signature against a public key it enrolled once, and issues a short-lived credential. No long-lived secret sits on disk, in an env var, or in a config file; there is nothing for a stolen laptop image or a leaked `.env` to give away.

This is the same pattern as AWS IAM Roles Anywhere, where a hardware-held X.509 key signs a challenge and the workload gets short-lived credentials through a `credential_process` helper. Signet is that idea generalised across the three secure-hardware substrates a real fleet actually has (Apple Secure Enclave, a TPM, a YubiKey/PIV token), and scoped to one broker's vend contract. The signing key never leaves the hardware; the only thing on disk is a short-lived bearer cache and, on macOS, the Enclave's own opaque key blob, useless if copied off the machine.

It is the machine-identity client for the [Portcullis](https://github.com/poodle64/portcullis) secrets broker, but it carries no broker code: it speaks the Portcullis `/v1/attest` HTTP contract and nothing more. No sidecar, no helper process, no PKCS#11 module to point at; the backends are compiled in and the binary detects the OS and the available hardware.

## Features

<table>
<tr>
<td width="50%"><strong>One binary, three backends</strong><br>Secure Enclave on Macs, a TPM on Linux servers, a YubiKey/PIV token anywhere; compiled in and selected at runtime, so switching hardware is a one-line env change, not a migration.</td>
<td width="50%"><strong>A credential helper, not a daemon</strong><br>The same shape as <code>git credential</code>, <code>docker-credential-*</code>, and AWS <code>credential_process</code>: a consumer shells out for a fresh bearer header on demand and holds no standing secret of its own.</td>
</tr>
<tr>
<td width="50%"><strong>Nothing exportable, nothing at rest</strong><br>The P-256 signing key is generated in hardware and never appears in a file, env var, log, or argv. The only persisted state is a short-lived bearer cache.</td>
<td width="50%"><strong>No software-key fallback, by design</strong><br>A host with no secure hardware fails loudly rather than quietly degrading to a key on disk, so "this identity is hardware-rooted" is never a claim that is sometimes false.</td>
</tr>
</table>

## Installation

```sh
brew install poodle64/tap/signet
```

For nix (home-manager / nix-darwin), a `fetchurl` + SRI derivation lives in [`nix/signet.nix`](nix/signet.nix); copy it into your config and add it to `home.packages`.

To install manually, download the per-platform tarball and checksum from the [latest release](https://github.com/poodle64/signet/releases/latest), verify, and put the binary on your `PATH`:

```sh
shasum -a 256 -c signet-*-*.tar.gz.sha256
tar -xzf signet-*-*.tar.gz
install -m755 signet ~/.local/bin/signet
```

Print the signing key's public half to enrol it with the broker:

```sh
signet enrol
```

See the [Usage guide](docs/usage.md) for the `sign` and `auth` commands and for wiring signet as a credential helper.

## Documentation

| Guide | What it covers |
| ----- | -------------- |
| [Usage](docs/usage.md) | The enrol, sign, and auth commands, and wiring signet as a credential helper |
| [Configuration](docs/configuration.md) | Environment variables, backend selection, and on-disk paths |
| [Hardware backends](docs/backends.md) | The Secure Enclave, TPM, and PIV backends in depth |
| [Building from source](docs/development/building.md) | The cgo build, the Swift shim, and the release toolchain |

## Contributing

```sh
make build       # builds ./signet
make test        # runs the test suite
```

cgo is required, which means per-platform native builds: the Secure Enclave and PIV backends link C (the Enclave via a Swift shim compiled by `make build`), so they cannot be cross-compiled; TPM is pure Go. Full details of the build, the Swift shim, and the release toolchain are in the [Building from source guide](docs/development/building.md).

<div align="center">
<sub>
The key that proves which machine you are; sealed in hardware, exportable to no one.<br>
<a href="LICENSE">MIT Licence</a> · <a href="https://github.com/poodle64/signet/issues">Report Bug</a>
</sub>
</div>
