// attest.go: broker attestation flow and bearer cache for the 'auth' subcommand.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// bearerCache is the on-disk structure stored under ~/.signet/cache/.
type bearerCache struct {
	Key          string    `json:"key"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxExpiresAt time.Time `json:"max_expires_at"`
}

// tokenResult is the broker's response to /v1/attest/token and /v1/attest/renew.
type tokenResult struct {
	Key          string `json:"key"`
	KeyID        string `json:"key_id"`
	Name         string `json:"name"`
	ExpiresAt    string `json:"expires_at"`
	MaxExpiresAt string `json:"max_expires_at"`
}

// challengeResult is the broker's response to /v1/attest/challenge.
type challengeResult struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	ExpiresAt   string `json:"expires_at"`
}

// canonicalMessage constructs the UTF-8 message the broker's attestation.py
// canonical_message() produces: "{challenge_id}.{nonce}".
// This is the string that must be SHA-256 digested and signed.
func canonicalMessage(challengeID, nonce string) string {
	return challengeID + "." + nonce
}

// sanitiseHost replaces URL structural characters with underscores to produce
// a safe filesystem filename component from a broker URL.
func sanitiseHost(brokerURL string) string {
	r := strings.NewReplacer("://", "_", "/", "_", ":", "_")
	return r.Replace(brokerURL)
}

// publicKeyFingerprint returns the first 16 hex characters of the SHA-256
// digest of the raw DER bytes encoded in spkiB64. This is the protocol-level
// fingerprint: 16 hex chars of SHA-256(SPKI DER), used by the /v1/attest
// protocol to discriminate bearer caches per enrolled key without sending the
// key identity by name. One fingerprint per enrolled key, independent of any
// broker-side identity name.
func publicKeyFingerprint(spkiB64 string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return "", fmt.Errorf("decode SPKI base64: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16], nil
}

// signetHome returns signet's single data directory (~/.signet). All persistent
// state — the SE key blobs and the bearer cache — lives under it, so one
// dotfolder holds everything signet writes (the household ~/.tool convention,
// not an XDG split across ~/.local/share and ~/.cache).
func signetHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".signet"), nil
}

// cacheDir returns the bearer-cache directory (~/.signet/cache), creating it
// (mode 0700) if needed.
func cacheDir() (string, error) {
	base, err := signetHome()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}
	return dir, nil
}

// cachePath returns the bearer-cache file path, keyed by broker URL AND the
// public key fingerprint so re-enrolling (a new key for the same broker) never
// serves a stale bearer minted for the old key.
func cachePath(brokerURL, fingerprint string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	name := sanitiseHost(brokerURL) + "_" + fingerprint + ".json"
	return filepath.Join(dir, name), nil
}

// loadCache reads the bearer cache from disk. Returns nil (not an error) if
// the file does not exist or cannot be parsed.
func loadCache(brokerURL, fingerprint string) *bearerCache {
	path, err := cachePath(brokerURL, fingerprint)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var bc bearerCache
	if err := json.Unmarshal(data, &bc); err != nil {
		return nil
	}
	return &bc
}

// saveCache writes the bearer cache to disk with mode 0600.
func saveCache(brokerURL, fingerprint string, bc *bearerCache) error {
	path, err := cachePath(brokerURL, fingerprint)
	if err != nil {
		return err
	}
	data, err := json.Marshal(bc)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}
	// Write atomically: write to a temp file then rename.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}

// parseExpiry parses an ISO-8601 timestamp from the broker, trying RFC3339Nano
// then RFC3339 as a fallback.
func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("cannot parse expiry %q as RFC3339", s)
}

// brokerPost sends a POST request with a JSON body to endpoint and decodes the
// JSON response into result. If bearerKey is non-empty, it is sent as an
// Authorization: Bearer header.
func brokerPost(endpoint string, body any, bearerKey string, result any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerKey != "" {
		req.Header.Set("Authorization", "Bearer "+bearerKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("broker %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// errUnauthorized is a sentinel used to distinguish a 401 on /renew from
// other errors, so the caller can fall through to a fresh attest.
var errUnauthorized = errors.New("unauthorized")

// bearerCacheFromToken parses the expiry timestamps from a tokenResult and
// assembles a bearerCache. Extracted because attestFresh and renewBearer share
// identical parsing logic.
func bearerCacheFromToken(tr tokenResult) (*bearerCache, error) {
	expiresAt, err := parseExpiry(tr.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	maxExpiresAt, err := parseExpiry(tr.MaxExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse max_expires_at: %w", err)
	}
	return &bearerCache{Key: tr.Key, ExpiresAt: expiresAt, MaxExpiresAt: maxExpiresAt}, nil
}

// attestFresh performs legs 1 and 2 of the attestation protocol:
// /v1/attest/challenge then /v1/attest/token.
//
// The broker resolves the identity from the presented public key (resolve-by-key,
// #73). Leg 1 sends {"public_key_der": <spki-b64>}; leg 2 sends only
// {challenge_id, nonce, signature_b64} — identity_id is not sent.
func attestFresh(signer Signer, brokerURL string) (*bearerCache, error) {
	// Obtain the enrolled public key; fail fast if no key has been enrolled.
	spkiB64, err := signer.PublicKeyDER()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	// Leg 1: request a challenge, presenting the public key.
	var cr challengeResult
	if err := brokerPost(brokerURL+"/v1/attest/challenge", map[string]string{"public_key_der": spkiB64}, "", &cr); err != nil {
		return nil, fmt.Errorf("attest/challenge: %w", err)
	}

	// Sign the canonical message via the backend-agnostic Signer interface.
	msg := canonicalMessage(cr.ChallengeID, cr.Nonce)
	sigB64, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("sign challenge: %w", err)
	}

	// Leg 2: exchange the signature for a bearer. identity_id is NOT sent —
	// the broker resolves the identity from the public key stored at leg 1.
	tokenBody := map[string]string{
		"challenge_id":  cr.ChallengeID,
		"nonce":         cr.Nonce,
		"signature_b64": sigB64,
	}
	var tr tokenResult
	if err := brokerPost(brokerURL+"/v1/attest/token", tokenBody, "", &tr); err != nil {
		return nil, fmt.Errorf("attest/token: %w", err)
	}
	return bearerCacheFromToken(tr)
}

// renewBearer attempts leg 3: POST /v1/attest/renew with the current bearer.
// Returns nil, nil when the broker returns 401 (max lifetime exceeded; caller
// should fall through to attestFresh).
func renewBearer(brokerURL, currentKey string) (*bearerCache, error) {
	var tr tokenResult
	err := brokerPost(brokerURL+"/v1/attest/renew", map[string]string{}, currentKey, &tr)
	if err != nil {
		if errors.Is(err, errUnauthorized) {
			return nil, nil // max lifetime exceeded; re-attest
		}
		return nil, fmt.Errorf("attest/renew: %w", err)
	}
	return bearerCacheFromToken(tr)
}

// cmdAuth is the credential-helper entry point. It tries the disk cache,
// renews when within 30 min of expiry, re-attests on 401 or past max lifetime,
// and prints {"Authorization":"Bearer <key>"} to stdout.
//
// The bearer cache is keyed by broker URL and the enrolled public key's
// fingerprint (resolve-by-key, #73). identity_id is no longer used.
func cmdAuth(signer Signer, brokerURL string) error {
	// Derive the fingerprint from the enrolled public key to key the cache.
	spkiB64, err := signer.PublicKeyDER()
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
	bc, err := attestFresh(signer, brokerURL)
	if err != nil {
		return err
	}
	// Best-effort; return the bearer even if we cannot cache it.
	_ = saveCache(brokerURL, fingerprint, bc)
	printAuthHeader(bc.Key)
	return nil
}

// printAuthHeader prints the Claude Code headersHelper JSON contract to stdout:
// {"Authorization":"Bearer <key>"} (compact, key order stable).
func printAuthHeader(key string) {
	type authJSON struct {
		Authorization string `json:"Authorization"`
	}
	out, _ := json.Marshal(authJSON{Authorization: "Bearer " + key})
	fmt.Println(string(out))
}
