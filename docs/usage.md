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
signet enrol [--backend <backend>] [--identity <name>] [--user-presence]
signet sign [--backend <backend>] [--identity <name>] <message>
signet auth [--backend <backend>] [--identity <name>] <broker-url>
```

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

The canonical message signed is `{challenge_id}.{nonce}`; signet speaks only the Portcullis `/v1/attest/{challenge,token,renew}` HTTP contract.

Re-runs reuse the cache and renew the bearer as it ages: a cached token still more than 30 minutes from expiry is reused as-is; within 30 minutes of expiry signet renews it; a `401` on renew (or a token past its maximum lifetime) triggers a fresh attestation. The cache is keyed by broker URL and identity, so one machine can hold separate bearers for several brokers or identities without collision.

## Wiring signet as a credential helper

A credential helper is a small program a consumer shells out to whenever it needs a fresh credential, instead of the consumer holding a standing secret of its own. `auth` fits that contract exactly: it prints an `Authorization` header on stdout and exits, and the consumer captures that output. There is no daemon, socket, or keepalive; signet runs once per request and exits, like `git credential` or AWS's `credential_process`.

For a Claude Code MCP `http` server, wire `auth` as the `headersHelper`. The backend is a flag (or auto-detected), so moving between a YubiKey, a TPM, and the Secure Enclave is a one-flag change:

```json
{
  "mcpServers": {
    "portcullis": {
      "type": "http",
      "url": "https://portcullis.example.internal/mcp",
      "headersHelper": "signet auth --backend piv https://portcullis.example.internal"
    }
  }
}
```

The bearer refreshes at each (re)connect: Claude Code re-runs the helper, and signet serves the cached bearer (renewing or re-attesting as needed). The same pattern works for any consumer that can shell out for an `Authorization` header; the MCP `headersHelper` is one instance of the general credential-helper contract, not a signet-specific feature.
