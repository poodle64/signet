# Configuration

signet is configured with per-subcommand flags. There are no mandatory environment variables; the only ambient configuration is an optional identity name for the Secure Enclave backend. For the hardware backends themselves see [backends.md](backends.md); for the commands see [usage.md](usage.md).

## Flags (accepted on every subcommand)

### --backend

Selects the hardware backend.

- **Values:** `secure-enclave` (aliases `enclave`, `se`), `tpm`, `piv`.
- **Default:** omitted, which triggers auto-detection (see [Backend selection](#backend-selection)).
- **Effect:** overrides auto-detection; an unrecognised value is an error rather than a silent fallback.

Switching hardware is a one-flag change: `--backend secure-enclave`, `--backend tpm`, or `--backend piv` — not a reconfiguration or a migration.

### --slot

Selects the PIV signing slot. Accepted values: `9a`, `9c`, `9d`, `9e`, or a retired key-management slot `82`–`95`. Defaults to `9c` (Digital Signature slot). Ignored on non-PIV backends. Each slot holds an independent keypair, so one YubiKey can root multiple distinct identities — one per slot, each with its own public key and its own broker enrolment.

### --identity

Names which hardware keypair to sign as — the **local label of a keypair**, exactly like the filename you give an SSH key. Defaults to `consumer`.

This is why the flag exists. A single machine can hold more than one consumer (say a browser-driver sidecar and a separate vend client), and each needs its own distinct keypair so the broker can tell them apart. Without a name there would be a single anonymous key slot per machine; with it you can have two consumers on one Mac, each with its own blob and its own enrolled public key.

The name is **purely local. It never crosses the wire to the broker.** signet sends the broker only the key's public half; the broker identifies a consumer by that public key, not by the name chosen locally. Renaming an identity does not change the key; it just looks in a different file.

Honoured by the Secure Enclave backend only. It names the on-disk key blob (`se-<identity>.key`). Characters outside `[a-zA-Z0-9._-]` are normalised to underscores in the filename, so `my/service` produces `se-my_service.key`. The TPM and PIV backends ignore it: their key lives at a fixed location in the hardware (a fixed TPM handle, or a PIV token slot), so each of those machines holds exactly one identity per slot.

### --user-presence

Secure-Enclave-only. Gates each subsequent signature behind Touch ID or the device passcode. Suits an interactive identity; on TPM and PIV this flag has no effect. Accepted only on `enrol`.

## Backend selection

signet resolves the backend in this order:

1. **`--backend` flag.** If passed, its value wins (`secure-enclave` / `enclave` / `se`, `tpm`, or `piv`). An unrecognised value is rejected.
2. **Auto-detect** (when `--backend` is omitted):
   - **macOS** uses the Secure Enclave.
   - **Linux and Windows** use the TPM if a TPM device is reachable, otherwise fall back to PIV.
   - **Anything else** uses PIV.

There is no software-key fallback at any step; a host with no secure hardware fails loudly rather than degrading to a key on disk (see [backends.md](backends.md#no-software-fallback)).

## On-disk paths

All of signet's persistent state lives under a single dotfolder, `~/.signet` (directory mode `0700`). signet holds no long-lived secret; the only things it writes are the short-lived bearer cache and, on macOS, the Secure Enclave's opaque key blob.

| Path | Mode | Backend | What it holds |
| --- | --- | --- | --- |
| `~/.signet/se-<identity>.key` | `0600` | Secure Enclave | The Enclave's opaque, hardware-wrapped key blob. `<identity>` is the value of `--identity` (default `consumer`). |
| `~/.signet/cache/<url>_<identity>.json` | `0600` | all | A short-lived bearer token. |

The Secure Enclave blob is the Enclave's own machine-bound, hardware-wrapped key material; it is useless if copied to another machine, because only this Mac's Enclave can unwrap it.

The bearer cache is keyed by both the broker URL and the identity, so one machine can hold separate bearers for several brokers or identities without collision. signet reuses a cached bearer until it nears expiry, renews it within 30 minutes of expiry, and re-attests from scratch if renewal is rejected. Deleting a cache file simply forces a fresh attestation on the next `auth`.

**The TPM and PIV backends persist nothing on disk** beyond the bearer cache. Their signing key lives inside the hardware (a fixed TPM handle, or a PIV token slot), so there is no on-disk key blob to protect; the only file either backend writes is the bearer cache above.
