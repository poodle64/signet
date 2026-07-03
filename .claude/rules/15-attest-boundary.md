---
paths:
  - '**/*'
---

# Signet Attest Boundary

signet is the machine-identity client of exactly one broker's attestation contract. This file is a per-repo amendment of the household master rule `rules-library/ai/sidekick-tooling.md`: it carries the **attestation-client corollary** of that rule's broker-black-box invariant. The broker implementation carries the verification side in a boundary rule of its own repository. The line both sides defend is the same one: signet proves possession of a hardware key, and every authorisation decision stays on the broker.

- Must follow `rules-library/core/00-rules-approach.md` §"Changing a rule or strategy" for shared-governance edits: as the attestation-client SME you may make a targeted, well-reasoned change to a shared sidekick-tooling invariant directly (recording why in the commit); raise an issue on `poodle64/master-project` for sweeping, cross-domain, or contentious changes. Must NOT weaken an invariant the broker side depends on without flagging it.

## 1. One contract, nothing more

signet speaks the broker attestation HTTP contract and only that contract: `POST /v1/attest/challenge`, `POST /v1/attest/token`, and `POST /v1/attest/renew` (the three legs in `internal/attest/attest.go`). The whole flow is three requests and a signature in between; there is no fourth endpoint, no sidecar, no helper process, no PKCS#11 module. A new broker capability does not earn signet a new code path unless it lands on this `/v1/attest/*` surface.

- The challenge leg, the sign step, and the token exchange are `attestFresh`; renewal is `renewBearer` (both in `internal/attest/attest.go`). These two functions are the entire broker conversation.

## 2. Vendor no broker code, reimplement no verification

signet imports no broker package and vendors no broker source. It constructs the request bodies the broker expects and decodes the responses the broker returns (`tokenResult`, `challengeResult` in `internal/attest/attest.go`); it does not reach inside the broker's logic. The broker is a black-box HTTP service reached over the wire, never a Go dependency linked in-process.

- Must NOT add a dependency on any broker module, copy broker code into this repo, or reimplement any broker-side step (challenge issuance, signature verification, bearer minting, scope evaluation). Those live on the broker; signet only produces the proof and consumes the token.

## 3. Zero authorisation decisions

signet's job is to prove which machine it is, not to decide what that machine may do. It signs the canonical challenge in hardware and hands the broker a signature; the broker alone verifies it, mints the bearer, and fixes the vend scope. signet never inspects, gates, or second-guesses a scope. A 401 is the broker exercising its authority, and signet's only response is to re-attest (`Auth` in `internal/attest/auth.go`; `renewBearer` treats a 401 as re-attest, never as an error to argue with), never to widen its own access.

- Must NOT add any allow/deny, scope-checking, or entitlement logic to signet. Authorisation is the broker's, in full, without exception.

## 4. The canonical signed message is the broker's

The string signet signs is `"{challenge_id}.{nonce}"`, built by `canonicalMessage` (`internal/attest/attest.go`) from the challenge leg's response and fed through the `Signer` interface's `Sign`. This must byte-for-byte match what the broker's `canonical_message()` constructs, or every signature fails verification. The format is the broker's to define; signet mirrors it and must not drift from it.

- Must keep `canonicalMessage` exactly aligned with the broker's canonical form; a change on either side is a coordinated, cross-repo change, never a unilateral edit here.
- Must sign the canonical message through the backend-agnostic `Signer` interface (`internal/signer/signer.go`), never against a specific backend, so the contract holds identically across Secure Enclave, TPM, and PIV.

## 5. `signet` naming only: no broker-brand coupling

signet's per-subcommand flags (`--backend`, `--slot`, `--identity`), its Secure Enclave key-blob filenames, and its data directory (`~/.signet`, `internal/datadir/datadir.go`) all carry the tool's own name. Configuration was originally broker-brand-prefixed env vars, then `SIGNET_*` env vars, and is now per-subcommand flags — removing the ambient-environment footgun and making each invocation self-documenting. The data directory and blob filenames have always been `~/.signet/`; that has not changed. The former env-var form was retired in 2026.6.4.

- Must NOT reintroduce any broker-brand prefix for a flag, env var, cache path, or data path; new configuration uses the `signet` / `--` prefix.
- Must NOT add a new ambient environment variable; configuration belongs in per-subcommand flags so each invocation is self-contained.

## 6. The credential-helper contract: emit one header and exit

signet `auth` is a credential helper of the same shape as `git credential`, `docker-credential-*`, and AWS `credential_process`: it emits one `{"Authorization":"Bearer <key>"}` header to stdout (`printAuthHeader`, `internal/attest/auth.go`) and exits. The auth flow runs no daemon, opens no socket, and runs no keepalive loop; the separate `agent` subcommand is the deliberate long-lived exception, and it never touches this broker contract (it serves pubkey/sign to local sockets only — `20-key-custody.md`). An `auth --agent <socket>` invocation still emits once and exits; only the signing hop goes via the agent. Token freshness is handled per-invocation: a healthy cache is reused, a near-expiry bearer is renewed within 30 minutes of expiry, and a 401 or a past-max-lifetime bearer triggers a fresh attest (`Auth`, `internal/attest/auth.go`). Recovery is **re-attest, not a background refresh**.

- Must keep `auth` single-shot: produce the header, exit. Must NOT add a long-running mode, a background refresher, or a keepalive loop; the consumer re-invokes signet when it needs a fresh header.
- Must keep stdout to the one header-JSON line; diagnostics go to stderr (`internal/attest/auth.go`), so a caller can consume stdout verbatim as the headers contract.

## Invariants

- Must speak only the `/v1/attest/{challenge,token,renew}` HTTP contract; must NOT add a non-attest broker endpoint, sidecar, or helper process.
- Must NOT import a broker module, vendor broker source, or reimplement any broker-side step (challenge issuance, signature verification, bearer minting, scope evaluation).
- Must make ZERO authorisation decisions; signet proves possession of a hardware key and the broker decides everything else. On a 401 the only response is re-attest.
- Must keep the canonical signed message `"{challenge_id}.{nonce}"` byte-for-byte aligned with the broker; treat any change as coordinated and cross-repo.
- Must sign through the `Signer` interface, never against one backend, so the contract is identical across all three substrates.
- Must use `signet` / `--` flag naming for all configuration; must NOT reintroduce a `SIGNET_*` env-var or any broker-brand prefix.
- Must keep `auth` a single-shot credential helper: emit one `{"Authorization":"Bearer <key>"}` line on stdout and exit; the auth flow must NOT run a daemon, socket, or keepalive loop (the `agent` subcommand is the sole long-lived mode, and it never speaks to the broker). Recovery is re-attest, never a background refresh.

## See also

- `20-key-custody.md`: the hardware-key custody invariants that back the proof this boundary relies on.
- `00-project-foundations.md`: project scope, architecture, and non-negotiable constraints.
- Master rule amended here: `rules-library/ai/sidekick-tooling.md` (the attestation-client corollary of the broker-black-box invariant).
- Broker-side counterpart: the boundary rule in the broker implementation's own repository.
