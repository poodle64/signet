# Usage

signet is a hardware-rooted signing CLI. It holds a non-exportable P-256 key in secure hardware, signs a broker's attestation challenge with it, and exchanges that proof for a short-lived bearer token it caches and hands to consumers.

For per-subcommand flags, on-disk paths, and backend selection see [configuration.md](configuration.md); for the three hardware backends and the security model see [backends.md](backends.md).

## How it works

```text
  enrol   ──▶  signet prints the hardware key's PUBLIC half (SPKI DER, base64).
               You paste it into the broker once. The private half never leaves hardware.

  auth    ──▶  signet asks the broker for a challenge, signs it in hardware, exchanges
               the signature for a short-lived bearer, caches it, and prints an
               {"Authorization":"Bearer …"} header. Re-runs reuse the cache and renew
               as the token ages.
```

`auth` is a credential helper, the same shape as `git credential`, `docker-credential-*`, and AWS's `credential_process`. A consumer (an MCP client, a script, a service) calls it on demand to get a fresh auth header; it never holds a standing secret of its own. signet makes no authorisation decision; every challenge issuance, signature verification, and bearer minting is the broker's.

## Commands

```text
signet enrol   [--backend <backend>] [--identity <name>] [--user-presence]
signet sign    [--backend <backend>] [--identity <name>] <message>
signet auth    [--backend <backend>] [--identity <name>] <broker-url>
signet verify  --broker <url> [--credential <name>] [--backend <backend>] [--identity <name>]
signet agent   --bind <socket>=<slot> [--bind ...] [--backend piv]
signet doctor  [--backend <backend>]
signet version
```

`enrol`, `sign`, `auth`, `verify`, and `doctor` also accept `--agent <socket>` to sign via a running agent (see [agent](#agent)) instead of opening local hardware.

### enrol

```text
signet enrol [--user-presence]
```

Prints the signing key's public half (SPKI DER, base64) to stdout for one-time enrolment with the broker. You paste that value into the broker once; the private half never leaves hardware.

`enrol` is non-destructive and idempotent: it reads an existing key (a prior enrol, or a `ykman`-provisioned PIV key) rather than overwriting it, so running it again prints the same public key.

`--user-presence` is Secure-Enclave-only. It gates each subsequent signature behind Touch ID or the device passcode, which suits an interactive identity rather than an unattended one. On the TPM and PIV backends the flag has no effect.

### sign

```text
signet sign <message>
```

Signs `<message>` in hardware and prints a base64 IEEE P1363 (`r||s`) ECDSA P-256 signature over SHA-256 of the message to stdout. This is for testing or bespoke flows; the routine path is `auth`, which signs the broker's challenge for you.

### auth

```text
signet auth [--backend <backend>] [--identity <name>] <broker-url>
```

Runs the full attestation flow against the broker at `<broker-url>`: requests a challenge, signs it in hardware with the selected key, exchanges the signature for a short-lived bearer, caches that bearer, and prints a compact `{"Authorization":"Bearer <token>"}` header to stdout.

The broker resolves the calling consumer by its enrolled public key (the SSH `authorized_keys` model); no identity id is presented or required. `--identity` selects which local keypair signs the challenge (defaults to `consumer`); `--backend` overrides auto-detection of the hardware backend.

The canonical message signed is `{challenge_id}.{nonce}`; signet speaks only the `/v1/attest/{challenge,token,renew}` HTTP contract.

Re-runs reuse the cache and renew the bearer as it ages: a cached token still more than 30 minutes from expiry is reused as-is; within 30 minutes of expiry signet renews it; a `401` on renew (or a token past its maximum lifetime) triggers a fresh attestation. The cache is keyed by broker URL and the enrolled public key's fingerprint (the first 16 hex characters of SHA-256 over the SPKI DER public key), so re-enrolling a new key for the same broker never serves a stale bearer minted for the old key.

### agent

```text
signet agent --bind <socket>=<slot> [--bind <socket>=<slot> ...] [--backend piv]
```

`agent` is the deliberate exception to signet's otherwise daemonless model. It exists for one problem: a workload that must attest but **cannot reach the hardware at all** — a container with no pcscd socket and no path to the YubiKey. Mounting the token into that container is the wrong trade-off, so instead one trusted process owns the token and signs on request, the way `ssh-agent` holds a key and signs for clients.

One `agent` process serves a Unix socket per `--bind`, and each socket is pinned to one slot at start-up. A client connecting to a socket can only ever sign with **that socket's** key: the slot is never taken from the request, so a compromised client cannot attest as another identity. Because the token is single-access, all bindings share one process and hardware access is serialised. The agent answers exactly two operations — return the public key, and sign a message — and **never generates or overwrites a key**; enrolment stays a deliberate, hands-on host operation.

A client reaches the agent with `--agent <socket>` on `sign`, `enrol`, or `auth`:

```text
signet auth --agent /run/signet/myapp.sock https://broker.example.internal
```

`--agent` swaps the local-hardware signer for one that forwards over the socket; nothing else changes, and the broker — which resolves identity by public key — neither knows nor cares that the signature came via the agent. A consuming application that wraps signet decides for itself how to configure the socket path it passes via `--agent`; signet has no environment variable of its own.

## Wiring signet as a credential helper

A credential helper is a small program a consumer shells out to whenever it needs a fresh credential, instead of the consumer holding a standing secret of its own. `auth` fits that contract exactly: it prints an `Authorization` header on stdout and exits, and the consumer captures that output. There is no daemon, socket, or keepalive; signet runs once per request and exits, like `git credential` or AWS's `credential_process`.

For a Claude Code MCP `http` server, wire `auth` as the `headersHelper`. The backend is a flag (or auto-detected), so moving between a YubiKey, a TPM, and the Secure Enclave is a one-flag change:

```json
{
  "mcpServers": {
    "broker": {
      "type": "http",
      "url": "https://broker.example.internal/mcp",
      "headersHelper": "signet auth --backend piv https://broker.example.internal"
    }
  }
}
```

The bearer refreshes at each (re)connect: Claude Code re-runs the helper, and signet serves the cached bearer (renewing or re-attesting as needed). The same pattern works for any consumer that can shell out for an `Authorization` header; the MCP `headersHelper` is one instance of the general credential-helper contract, not a signet-specific feature.

### verify

```text
signet verify --broker <url> [--credential <name>] [--backend <backend>] [--identity <name>] [--agent <socket>]
```

`verify` is the consumer pre-flight command. It runs the full attestation round-trip against the broker and, if `--credential` is supplied, probes whether the enrolled identity has vend scope for that credential. It is designed to be called from a health check, a CI gate, or a deployment script to confirm the machine is correctly enrolled before doing real work.

`verify` prints a short diagnostic table to stdout and exits with a typed exit code:

| Code | Meaning |
| --- | --- |
| `0` | Success: attestation accepted; credential resolvable (if `--credential` given). |
| `1` | Unexpected transport or argument error. |
| `2` | Key missing: no key enrolled for this identity and backend. |
| `3` | Attestation rejected: the broker refused the attestation (4xx). |
| `4` | Credential out of scope: the identity is attested but the credential is not in its vend scope (403). |
| `5` | Credential not found: the credential name is absent from the broker's catalogue (404). |

Example output (successful attestation, credential probed):

```text
signet verify — broker: https://broker.example.internal

  key              OK             key present
  attest           OK             bearer minted
  credential my-cred      OK             resolvable

result: OK
```

Example for a machine not yet enrolled:

```text
signet verify — broker: https://broker.example.internal

  key              FAIL           no key enrolled: open ~/.signet/se-consumer.key: no such file or directory

result: key missing (exit 2)
```

### doctor

```text
signet doctor [--backend <backend>] [--identity <name>] [--agent <socket>]
```

`doctor` probes each compiled-in backend and reports whether the underlying hardware is present and reachable. It is the first thing to run when setting up a new machine or diagnosing a failure.

Without `--backend`, `doctor` probes all three backends and shows their status side by side. Passing `--backend` narrows the check to that one backend.

Example output (all three backends, macOS without a TPM or YubiKey):

```text
signet doctor — platform: darwin/arm64

  secure-enclave     OK             CryptoKit reports Secure Enclave present
  tpm                UNAVAILABLE    no TPM device found (/dev/tpmrm0, /dev/tpm0, or TBS)
  piv                UNAVAILABLE    no smart cards / YubiKeys detected
```

Example with `--backend secure-enclave`:

```text
signet doctor — platform: darwin/arm64

  secure-enclave     OK             CryptoKit reports Secure Enclave present
```

`doctor` exits `0` if at least one probed backend is `OK`, and `1` if all probed backends are unavailable or failed.

### version

```text
signet version
```

Prints the signet version, platform, and Go runtime. The format is:

```text
signet v2026.6.6 darwin/arm64 (go1.25.10)
```
