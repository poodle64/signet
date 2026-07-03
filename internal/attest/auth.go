// auth.go: the 'signet auth' credential-helper flow.
package attest

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/poodle64/signet/internal/signer"
)

// Auth is the credential-helper entry point. It tries the disk cache,
// renews when within 30 min of expiry, re-attests on 401 or past max lifetime,
// and prints {"Authorization":"Bearer <key>"} to stdout.
//
// The bearer cache is keyed by broker URL and the enrolled public key's
// fingerprint (resolve-by-key, #73).
func Auth(s signer.Signer, brokerURL string) error {
	// Derive the fingerprint from the enrolled public key to key the cache.
	spkiB64, err := s.PublicKeyDER()
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}
	fingerprint, err := publicKeyFingerprint(spkiB64)
	if err != nil {
		return fmt.Errorf("compute key fingerprint: %w", err)
	}

	if cached := loadCache(brokerURL, fingerprint); cached != nil {
		ttl := time.Until(cached.ExpiresAt)
		maxAlive := time.Until(cached.MaxExpiresAt)
		if ttl > 0 && maxAlive > 0 {
			if ttl > 30*time.Minute {
				// Cache is healthy; reuse it.
				printAuthHeader(cached.Key)
				return nil
			}
			// Within 30 minutes of expiry; try to renew.
			renewed, err := renewBearer(brokerURL, cached.Key)
			if err != nil {
				// Renewal failed (network or broker error); fall through to re-attest.
				fmt.Fprintf(os.Stderr, "signet: renew failed, re-attesting: %v\n", err)
			} else if renewed != nil {
				// Best-effort save; still return the key even if the write fails.
				_ = saveCache(brokerURL, fingerprint, renewed)
				printAuthHeader(renewed.Key)
				return nil
			}
			// renewed == nil means 401; fall through to fresh attest.
		}
	}

	// Fresh attestation.
	bc, err := attestFresh(s, brokerURL)
	if err != nil {
		return err
	}
	// Best-effort; return the bearer even if we cannot cache it.
	_ = saveCache(brokerURL, fingerprint, bc)
	printAuthHeader(bc.Key)
	return nil
}

// printAuthHeader prints the credential-helper headers contract to stdout:
// {"Authorization":"Bearer <key>"} (compact JSON, one line), the shape
// consumers ingest verbatim as HTTP headers.
func printAuthHeader(key string) {
	type authJSON struct {
		Authorization string `json:"Authorization"`
	}
	out, _ := json.Marshal(authJSON{Authorization: "Bearer " + key})
	fmt.Println(string(out))
}
