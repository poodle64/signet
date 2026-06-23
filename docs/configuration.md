# Configuration

signet reads exactly two environment variables. Everything else (the broker URL,
the identity) is a command argument; see [usage.md](usage.md). For the hardware
backends themselves see [backends.md](backends.md).

## Environment variables

### SIGNET_BACKEND

Selects which hardware backend to use.

- **Accepted values:** `secure-enclave` (aliases `enclave`, `se`), `tpm`, `piv`.
- **Default:** unset, which triggers auto-detection (see [Backend selection](#backend-selection)).
- **Honoured by:** all platforms. It overrides auto-detection; an unknown value is
  an error rather than a silent fallback.

### SIGNET_IDENTITY

Selects which identity to sign as.

- **Accepted values:** any identity name.
- **Default:** `consumer`. signet's common case is a credential consumer attesting
  for a vend, so an unconfigured caller resolves to the consumer identity; set an
  explicit value for an admin or any per-service identity.
- **Honoured by:** the Secure Enclave backend only. It names the on-disk key blob
  (`se-<identity>.key`), so one Mac can hold more than one identity. Characters
  outside `[a-zA-Z0-9._-]` are normalised to underscores in the filename (the
  `safeFilename` helper in `signer_darwin.go`), so an identity `my/service`
  produces `se-my_service.key`. It is not a keychain attribute. The TPM and PIV
  backends ignore it: their key lives at a fixed location in the hardware, not in a
  per-identity file.

There is no `SIGNET_SE_TAG` or any other variable; these two are the entire
configuration surface.

## Backend selection

signet resolves the backend in this order:

1. **`SIGNET_BACKEND` override.** If set, its value wins (`secure-enclave` /
   `enclave` / `se`, `tpm`, or `piv`). An unrecognised value is rejected.
2. **Auto-detect** (when `SIGNET_BACKEND` is unset):
   - **macOS** uses the Secure Enclave.
   - **Linux and Windows** use the TPM if a TPM device is reachable, otherwise
     fall back to PIV.
   - **Anything else** uses PIV.

There is no software-key fallback at any step; a host with no secure hardware fails
loudly rather than degrading to a key on disk (see
[backends.md](backends.md#no-software-fallback)).

## On-disk paths

All of signet's persistent state lives under a single dotfolder, `~/.signet`
(directory mode `0700`). signet holds no long-lived secret; the only things it
writes are the short-lived bearer cache and, on macOS, the Secure Enclave's opaque
key blob.

| Path | Mode | Backend | What it holds |
| --- | --- | --- | --- |
| `~/.signet/se-<identity>.key` | `0600` | Secure Enclave | The Enclave's opaque, hardware-wrapped key blob. `<identity>` is the value of `SIGNET_IDENTITY` (default `consumer`). |
| `~/.signet/cache/<url>_<identity>.json` | `0600` | all | A short-lived bearer token. |

The Secure Enclave blob is the Enclave's own machine-bound, hardware-wrapped key
material; it is useless if copied to another machine, because only this Mac's
Enclave can unwrap it.

The bearer cache is keyed by both the broker URL and the identity, so one machine
can hold separate bearers for several brokers or identities without collision.
signet reuses a cached bearer until it nears expiry, renews it within 30 minutes
of expiry, and re-attests from scratch if renewal is rejected. Deleting a cache
file simply forces a fresh attestation on the next `auth`.

**The TPM and PIV backends persist nothing on disk** beyond the bearer cache. Their
signing key lives inside the hardware (a fixed TPM handle, or a PIV token slot),
so there is no on-disk key blob to protect; the only file either backend writes is
the bearer cache above.
