// bearer.go: the one path every subcommand takes to hold a bearer — disk cache
// first, renew near expiry, fresh attestation last, single-flighted across
// processes.
//
// Every subcommand needs the same thing (a live bearer) but only `auth` used to
// consult the cache; `headers`, `exec`, `vend-to-file` and `verify` each called
// attestFresh directly. That is three broker round-trips and a hardware
// signature per invocation, and the invocations are not spread out: a Claude
// Code session with N gate-served MCP servers runs N headersHelper processes at
// once. Measured 2026-08-14 on a 26-server project — 26 concurrent
// attestations, a median 12s and worst-case 29s to return a header, and the
// broker (correctly) shedding load with 429s and 401s. Claude Code read the
// failures as an auth-discovery problem and reported "Incompatible auth server:
// does not support dynamic client registration" against every one of them.
package attest

import (
	"fmt"
	"os"
	"time"

	"github.com/poodle64/signet/internal/signer"
)

// renewWindow is how close to expiry a cached bearer is renewed rather than
// reused. Shared by the cache read below and documented in docs/usage.md.
const renewWindow = 30 * time.Minute

// bearer returns a live bearer for this broker: the cached one while it is
// healthy, a renewed one near expiry, a freshly attested one otherwise.
//
// Concurrent callers single-flight through a lock on the cache file, so a cold
// or expired cache costs ONE attestation however many processes want it — the
// stampede is the failure mode this exists to prevent, and it is exactly what a
// session start produces. A caller that cannot take the lock still proceeds
// (locking is an optimisation, never a correctness gate), so a platform without
// it, or a stale lock, degrades to the old behaviour rather than blocking.
func bearer(s signer.Signer, brokerURL string) (*bearerCache, error) {
	spkiB64, err := s.PublicKeyDER()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	fingerprint, err := publicKeyFingerprint(spkiB64)
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}

	if bc := usableCache(brokerURL, fingerprint); bc != nil {
		return bc, nil
	}

	// Cache missing, expired, or inside the renew window. Serialise here: the
	// holder does the work, the waiters re-read what it wrote.
	unlock := lockCache(brokerURL, fingerprint)
	defer unlock()

	// Re-check under the lock — a waiter released here almost always finds the
	// bearer the holder just minted, which is the whole point.
	if bc := usableCache(brokerURL, fingerprint); bc != nil {
		return bc, nil
	}

	if cached := loadCache(brokerURL, fingerprint); cached != nil {
		if time.Until(cached.ExpiresAt) > 0 && time.Until(cached.MaxExpiresAt) > 0 {
			// Inside the renew window: leg 3 is one round-trip against three.
			renewed, renewErr := renewBearer(brokerURL, cached.Key)
			if renewErr != nil {
				fmt.Fprintf(os.Stderr, "signet: renew failed, re-attesting: %v\n", renewErr)
			} else if renewed != nil {
				_ = saveCache(brokerURL, fingerprint, renewed)
				return renewed, nil
			}
			// renewed == nil means the broker returned 401 (past max lifetime);
			// fall through to a fresh attestation.
		}
	}

	bc, err := attestFresh(s, brokerURL)
	if err != nil {
		return nil, err
	}
	// Best-effort: an uncacheable bearer is still a usable one.
	_ = saveCache(brokerURL, fingerprint, bc)
	return bc, nil
}

// usableCache returns the cached bearer when it is live and comfortably clear
// of expiry, else nil. "Comfortably" is renewWindow: a bearer inside it is
// renewed rather than handed out, so a long-running consumer never receives one
// about to expire mid-use.
func usableCache(brokerURL, fingerprint string) *bearerCache {
	cached := loadCache(brokerURL, fingerprint)
	if cached == nil {
		return nil
	}
	if time.Until(cached.MaxExpiresAt) <= 0 {
		return nil
	}
	if time.Until(cached.ExpiresAt) <= renewWindow {
		return nil
	}
	return cached
}
