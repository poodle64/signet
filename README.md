# signet

A **hardware-rooted signing CLI** — one self-contained, cross-platform Go binary that proves _which machine_ you are, using whatever secure hardware the machine has. `signet` holds a non-exportable P-256 signing identity in hardware (Apple Secure Enclave, a TPM, or a YubiKey/PIV token), signs a broker's attestation challenge with it, and exchanges that proof for a short-lived bearer token it caches and hands to consumers.

It is the machine-identity client for the [Portcullis](https://github.com/poodle64/portcullis) secrets broker, but it has no broker code in it: it speaks Portcullis's `/v1/attest` HTTP contract and nothing more. No sidecar, no helper process, no PKCS#11 module to point at — the backends are compiled in and the binary detects the OS and the available hardware.

## Why signet?

A machine that needs secrets has to prove it is itself before a broker will hand anything over. The robust way to do that is a **non-exportable key sealed in hardware**: the machine signs a challenge, the broker verifies the signature against a public key it enrolled once, and issues a short-lived credential. No long-lived secret sits on disk, in an env var, or in a config file — there is nothing for a stolen laptop image or a leaked `.env` to give away.

This is the same pattern as **AWS IAM Roles Anywhere**: a hardware-held X.509 key signs a challenge and the workload gets short-lived credentials through a `credential_process` helper. signet is that idea, generalised across the three secure-hardware substrates a real fleet actually has, and scoped to one broker's vend contract:

- **One binary, three backends.** Secure Enclave on Macs, a TPM on Linux servers, a YubiKey/PIV token anywhere. Switching hardware is a one-line env change, not a migration — the identity model and the broker contract are identical across all three.
- **A thin, honest client, not a framework.** The hardware-signing half is standard library reuse (`go-tpm`, `go-piv`, Apple CryptoKit). The protocol half — challenge → sign → token → renew — is deliberately small and specific to the broker's contract, because that is exactly what a credential helper is: the client to one server's auth flow. SPIRE, mTLS meshes, and full PKI are heavier answers to a problem a single broker does not have.
- **Nothing exportable, nothing persistent.** The signing key never leaves the hardware. The only thing on disk is a short-lived bearer cache and (on macOS) the Enclave's own opaque, machine-bound key blob — useless if copied off the machine.

## How it works

```text
  enrol   ──▶  signet prints the hardware key's PUBLIC half (SPKI DER, base64).
               You paste it into the broker once. The private half never leaves hardware.

  auth    ──▶  signet asks the broker for a challenge, signs it in hardware, exchanges
               the signature for a short-lived bearer, caches it, and prints an
               {"Authorization": "Bearer …"} header. Re-runs reuse the cache and renew
               as the token ages.
```

`auth` is a **credential helper** — the same shape as `git credential`, `docker-credential-*`, and AWS's `credential_process`. A consumer (an MCP client, a script, a service) calls it on demand to get a fresh auth header; it never holds a standing secret of its own.

## Backends — compiled in, auto-detected

| Backend | Library | OS | Works unsigned? | Status |
| --- | --- | --- | --- | --- |
| **TPM 2.0** | `github.com/google/go-tpm` (pure Go) | Linux, Windows | **Yes** | Proven end-to-end against the go-tpm software simulator (enrol + sign + verify). |
| **YubiKey / PIV** (slot 9c) | `github.com/go-piv/piv-go/v2` (cgo, PC/SC) | macOS, Linux, Windows | **Yes** | Builds and format-verified; real-hardware validation pending a physical key. |
| **Secure Enclave** | CryptoKit/Swift shim via cgo | macOS | **Yes** | Proven end-to-end on an unsigned ad-hoc binary (enrol + sign + verify). Self-stored-blob model — no keychain, no entitlement, no code signing. |

Selection: `SIGNET_BACKEND` (`tpm` \| `piv` \| `secure-enclave`) overrides; otherwise auto-detect — macOS → Secure Enclave; Linux/Windows → TPM if a TPM device is reachable, else PIV; anything else → PIV.

There is **no software-key fallback by design**: a host with no secure hardware genuinely cannot produce a hardware-rooted identity, and signet says so rather than quietly degrading to a key on disk.

### The Secure Enclave backend — no signing required

The SE backend uses **CryptoKit's self-stored-key-blob model** (the same approach as [`age-plugin-se`](https://github.com/remko/age-plugin-se)). `signet enrol` asks CryptoKit to create a P-256 key inside the Secure Enclave; the Enclave returns an opaque, hardware-wrapped key blob, which signet stores in a file (`~/.signet/se-<tag>.key`). The keychain is never touched.

Because the keychain is bypassed, **no `com.apple.application-identifier` entitlement and no code signature are needed**. The old keychain path required that entitlement and failed on unsigned binaries with `-34018 errSecMissingEntitlement`; the blob path avoids it entirely. Notarisation is irrelevant — it is a Gatekeeper distribution gate, not a runtime Secure-Enclave gate. The blob is bound to this Mac's Enclave and is useless if copied to another machine.

## Install

### Homebrew

```sh
brew install poodle64/tap/signet
```

### nix (home-manager / nix-darwin)

A `fetchurl` + SRI derivation for the per-platform release binary lives in [`nix/signet.nix`](nix/signet.nix). Copy it into your config and add it to `home.packages`:

```nix
home.packages = [ (pkgs.callPackage ./signet.nix { }) ];
```

### Manual

Download the per-platform tarball and checksum from the [latest release](https://github.com/poodle64/signet/releases/latest), verify it, and put the binary on your `PATH`:

```sh
shasum -a 256 -c signet-*-*.tar.gz.sha256
tar -xzf signet-*-*.tar.gz
install -m755 signet ~/.local/bin/signet
```

## Usage

```text
signet enrol [--user-presence]
signet sign <message>
signet auth <broker-url> <identity-id>
```

- **`enrol [--user-presence]`** — print the signing key's public half (SPKI DER, base64) to enrol with the broker. Non-destructive and idempotent: reads an existing key (a prior enrol, or a `ykman`-provisioned PIV key) rather than overwriting. `--user-presence` (Secure Enclave only) gates each signature behind Touch ID / passcode — for an interactive identity, not an unattended one.
- **`sign <message>`** — sign with SHA-256 / ECDSA-P256 and print the base64 IEEE P1363 (`r||s`) signature.
- **`auth <broker-url> <identity-id>`** — attest (challenge → sign → token), cache the bearer (`~/.signet/cache/`, keyed by broker **and** identity, renewing as it ages), and print `{"Authorization":"Bearer …"}`.

## Wiring it into a credential helper

`auth` produces an auth header on demand. For a Claude Code MCP `http` server, wire it as the `headersHelper`; the backend is just an env var (or auto-detected), so moving between a YubiKey, a TPM, and the Secure Enclave is a one-line change:

```json
{
  "mcpServers": {
    "portcullis": {
      "type": "http",
      "url": "https://portcullis.example.internal/mcp",
      "headersHelper": "SIGNET_BACKEND=piv signet auth https://portcullis.example.internal <identity-id>"
    }
  }
}
```

The bearer refreshes at each (re)connect. The same pattern works for any consumer that can shell out for an `Authorization` header.

## Configuration (environment)

- `SIGNET_BACKEND` — `tpm` \| `piv` \| `secure-enclave` (optional; auto-detected if unset).
- `SIGNET_IDENTITY` — selects which identity to sign as (optional; default `consumer`). Names the on-disk Secure-Enclave key-blob (`se-<identity>.key`), letting one Mac hold more than one identity. The default suits the common case — a credential consumer attesting for a vend; select an admin or any per-service identity with an explicit value. Not a keychain attribute.

## Build from source

cgo is required (the Secure Enclave and PIV backends link C libraries). On **macOS**, the SE backend links a small Swift shim (`se_swift.swift`) compiled to a static archive; `make build` runs the `xcrun swiftc` step then the Go build. The Swift runtime ships with macOS, so the binary is self-contained — no sidecar, no helper. On **Linux/Windows** there is no Swift step, so `make build` (or `CGO_ENABLED=1 go build`) is sufficient.

```sh
make build       # builds ./signet
make test        # runs the test suite
```

cgo means **per-platform native builds** (the SE and PIV backends cannot be cross-compiled); TPM is pure Go. The go-tpm software simulator (test-only) is behind the `tpmsimulator` build tag so its OpenSSL dependency stays out of normal builds.

## Security model

- The signing key is generated in hardware and is **non-exportable** — it never appears in a file, an env var, or a log.
- signet holds **no long-lived secret**. The bearer cache holds only short-lived tokens scoped to one broker and one identity; deleting it just forces a re-attest.
- The public key you enrol is the trust anchor. Enrolment is a deliberate, operator-mediated act (you paste the public key into the broker), not trust-on-first-use.
- A signature proves possession of the hardware key for one specific challenge; it cannot be replayed against a different challenge.

## License

[MIT](LICENSE).
