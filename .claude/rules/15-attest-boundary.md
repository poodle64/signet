---
paths:
  - '**/internal/attest/**'
  - '**/cmd/signet/**'
---

# Signet Attest Boundary

signet is the machine-identity client of exactly one broker's attestation contract. This file is signet's per-repo amendment of `rules-library/sidekick/sidekick-tooling.md`, carrying the **attestation-client corollary** of that rule's broker-black-box invariant; the broker repo carries the verification side. The line both defend is the same: signet proves possession of a hardware key, and every authorisation decision stays on the broker. Change a shared sidekick-tooling invariant per `core/rules-approach.md` §"Changing a rule or strategy" — a targeted SME edit here is fine (record why in the commit), but must NOT weaken an invariant the broker side depends on without flagging it.

## 1. One contract, nothing more

signet speaks the attestation HTTP contract and only that: `POST /v1/attest/{challenge,token,renew}` — the challenge leg, sign step, and token exchange are `attestFresh`, renewal is `renewBearer` (both `internal/attest/attest.go`). One bounded exception: the consumer helpers (`verify`, `headers`, `vend-to-file`, `exec`) also call `GET /v1/credentials/{name}`, the broker's public consumer vend door, authenticated by the bearer the attest legs mint — its stable consumer contract, not a private surface.

- Must NOT add a broker endpoint beyond the `/v1/attest/*` legs and the public `/v1/credentials/{name}` vend door; no sidecar, helper process, or PKCS#11 module. A new broker capability earns no code path unless it lands on those surfaces.

## 2. Vendor no broker code, reimplement no verification

signet imports no broker package and vendors no broker source: it builds the request bodies the broker expects and decodes its responses (`tokenResult`, `challengeResult`, `internal/attest/attest.go`), reaching inside none of its logic. The broker is a black-box HTTP service, never a Go dependency.

- Must NOT depend on a broker module, copy broker code here, or reimplement any broker-side step (challenge issuance, signature verification, bearer minting, scope evaluation).

## 3. Zero authorisation decisions

signet proves which machine it is, not what it may do. It signs the canonical challenge and hands over a signature; the broker alone verifies, mints the bearer, and fixes the vend scope. A 401 is the broker exercising its authority — the only response is to re-attest (`Auth`, `internal/attest/auth.go`; `renewBearer` treats a 401 as re-attest, never an error), never to widen access.

- Must NOT add any allow/deny, scope-checking, or entitlement logic. Authorisation is the broker's, in full.

## 4. The canonical signed message is the broker's

signet signs `"{challenge_id}.{nonce}"`, built by `canonicalMessage` (`internal/attest/attest.go`) and fed through the `Signer` interface's `Sign`. This must byte-for-byte match the broker's `canonical_message()`, or every signature fails verification; the format is the broker's to define.

- Must keep `canonicalMessage` byte-for-byte aligned with the broker — a change on either side is coordinated and cross-repo, never unilateral.
- Must sign through the backend-agnostic `Signer` interface (`internal/signer/signer.go`), never a specific backend, so the contract holds identically across SE, TPM, and PIV.

## 5. `signet` naming only: no broker-brand coupling

Flags (`--backend`, `--slot`, `--identity`), SE blob filenames, and the data dir (`~/.signet`, `internal/datadir/datadir.go`) all carry the tool's own name. Configuration is per-subcommand flags — no ambient environment; the former `SIGNET_*` env-var form was retired in 2026.6.4.

- Must NOT reintroduce a broker-brand prefix for any flag, env var, or path, nor add an ambient environment variable; configuration belongs in per-subcommand flags so each invocation is self-contained.

## 6. The credential-helper contract: emit one header and exit

`auth` is a credential helper of the `git credential` / `docker-credential-*` / AWS `credential_process` shape: it emits one `{"Authorization":"Bearer <key>"}` line to stdout (`printAuthHeader`, `internal/attest/auth.go`) and exits — no daemon, socket, or keepalive. A healthy cache is reused, a near-expiry bearer renewed within 30 min of expiry, and a 401 or past-max-lifetime bearer triggers a fresh attest (`Auth`). Recovery is **re-attest, not background refresh**. `auth --agent` still emits once and exits; only the signing hop goes via the agent, which never speaks to the broker (`20-key-custody.md`).

- Must keep `auth` single-shot: produce the header, exit — no long-running mode, background refresher, or keepalive. stdout carries only the one header-JSON line; diagnostics go to stderr, so a caller can consume stdout verbatim.

## See also

- `20-key-custody.md`: the hardware-key custody backing this proof.
- Amended master rule: `rules-library/sidekick/sidekick-tooling.md`; the broker-side counterpart lives in the broker repo.
