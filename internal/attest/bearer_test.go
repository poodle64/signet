// bearer_test.go: tests for the shared cached-bearer path every subcommand now
// takes. The behaviour under test is what the consumer helpers did NOT do
// before: consult the cache, and single-flight a cold one across processes.
//
// Every token the shared fake brokers mint is stamped from fakeNow (a fixed
// date in the past), so a cache written from one is already expired — which is
// precisely why the pre-existing suite never exercised the cache. These tests
// therefore write the cache directly with a live expiry.
package attest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeJSON encodes v as the response body, failing the test on an encode
// error rather than swallowing it into a confusing broker response.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode fake broker response: %v", err)
	}
}

// countingBroker serves the attest legs plus a credential vend, counting hits
// on each attest endpoint so a test can assert how many round-trips happened.
type countingBroker struct {
	server    *httptest.Server
	challenge atomic.Int32
	token     atomic.Int32
	renew     atomic.Int32
}

// newCountingBroker builds a broker whose minted bearers expire tokenTTL from
// NOW (not fakeNow), so what it mints is genuinely cacheable.
func newCountingBroker(t *testing.T, tokenTTL time.Duration) *countingBroker {
	t.Helper()
	cb := &countingBroker{}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, _ *http.Request) {
		cb.challenge.Add(1)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, challengeResult{
			ChallengeID: "ch-bearer-test",
			Nonce:       "bearernonce",
			ExpiresAt:   time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/v1/attest/token", func(w http.ResponseWriter, _ *http.Request) {
		cb.token.Add(1)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, tokenResult{
			Key:          "fresh-bearer-key",
			KeyID:        "kid-b1",
			Name:         "test-identity",
			ExpiresAt:    time.Now().Add(tokenTTL).Format(time.RFC3339),
			MaxExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/v1/attest/renew", func(w http.ResponseWriter, _ *http.Request) {
		cb.renew.Add(1)
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, tokenResult{
			Key:          "renewed-bearer-key",
			KeyID:        "kid-b1",
			Name:         "test-identity",
			ExpiresAt:    time.Now().Add(tokenTTL).Format(time.RFC3339),
			MaxExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	})

	cb.server = httptest.NewServer(mux)
	t.Cleanup(cb.server.Close)
	return cb
}

// seedCache writes a bearer cache for the stub signer's key expiring in ttl.
func seedCache(t *testing.T, brokerURL, key string, ttl time.Duration) {
	t.Helper()
	fp := mustFingerprint(t, stubSPKI)
	bc := &bearerCache{
		Key:          key,
		ExpiresAt:    time.Now().Add(ttl),
		MaxExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := saveCache(brokerURL, fp, bc); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
}

// TestBearer_ReusesWarmCache is the whole point of the change: a healthy cached
// bearer must cost zero broker round-trips. Every gate-served MCP server in a
// session runs this path at once, so one round-trip each is the difference
// between a session starting and the broker shedding load.
func TestBearer_ReusesWarmCache(t *testing.T) {
	setTempHome(t)
	cb := newCountingBroker(t, 2*time.Hour)
	seedCache(t, cb.server.URL, "warm-bearer-key", 2*time.Hour)

	got, err := bearer(&stubSigner{sig: "c2ln"}, cb.server.URL)
	if err != nil {
		t.Fatalf("bearer: %v", err)
	}
	if got.Key != "warm-bearer-key" {
		t.Errorf("key = %q, want the cached one", got.Key)
	}
	if n := cb.challenge.Load() + cb.token.Load() + cb.renew.Load(); n != 0 {
		t.Errorf("broker round-trips = %d, want 0 on a warm cache", n)
	}
}

// TestBearer_RenewsInsideWindow asserts a bearer close to expiry takes the
// one-round-trip renew leg rather than a full three-leg attestation.
func TestBearer_RenewsInsideWindow(t *testing.T) {
	setTempHome(t)
	cb := newCountingBroker(t, 2*time.Hour)
	seedCache(t, cb.server.URL, "expiring-bearer-key", renewWindow/2)

	got, err := bearer(&stubSigner{sig: "c2ln"}, cb.server.URL)
	if err != nil {
		t.Fatalf("bearer: %v", err)
	}
	if got.Key != "renewed-bearer-key" {
		t.Errorf("key = %q, want the renewed one", got.Key)
	}
	if n := cb.renew.Load(); n != 1 {
		t.Errorf("renew calls = %d, want 1", n)
	}
	if n := cb.challenge.Load(); n != 0 {
		t.Errorf("challenge calls = %d, want 0 — renewal should avoid a fresh attest", n)
	}
}

// TestBearer_SingleFlightsColdCallers is the stampede guard. Concurrent callers
// finding a cold cache must produce ONE attestation between them, not one each:
// the failure this replaces was 26 simultaneous attestations from a single
// session start, which the broker rate-limited.
func TestBearer_SingleFlightsColdCallers(t *testing.T) {
	setTempHome(t)
	cb := newCountingBroker(t, 2*time.Hour)

	const callers = 12
	var wg sync.WaitGroup
	keys := make([]string, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bc, err := bearer(&stubSigner{sig: "c2ln"}, cb.server.URL)
			errs[i] = err
			if bc != nil {
				keys[i] = bc.Key
			}
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if keys[i] != "fresh-bearer-key" {
			t.Errorf("caller %d key = %q, want the attested one", i, keys[i])
		}
	}
	if n := cb.challenge.Load(); n != 1 {
		t.Errorf("challenge calls = %d, want exactly 1 across %d concurrent callers", n, callers)
	}
	if n := cb.token.Load(); n != 1 {
		t.Errorf("token calls = %d, want exactly 1 across %d concurrent callers", n, callers)
	}
}

// TestHeaders_ReusesWarmCache proves the wiring reached the consumer helper the
// MCP fleet actually calls, not only the shared function.
func TestHeaders_ReusesWarmCache(t *testing.T) {
	setTempHome(t)
	var attests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, _ *http.Request) {
		attests.Add(1)
		http.Error(w, "should not be called", http.StatusTooManyRequests)
	})
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer warm-bearer-key" {
			http.Error(w, "wrong bearer", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"material":{"kind":"static","fields":[{"name":"api_key","value":"vended"}]}}`)) //nolint:errcheck
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	seedCache(t, srv.URL, "warm-bearer-key", 2*time.Hour)

	var code int
	stdout, stderr := captureHeadersOutput(t, func() {
		code, _ = Headers(&stubSigner{sig: "c2ln"}, srv.URL, "some-cred", "Authorization", "bearer", false)
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if attests.Load() != 0 {
		t.Errorf("attest/challenge calls = %d, want 0 — headers must reuse the cache", attests.Load())
	}
	if want := `{"Authorization":"Bearer vended"}`; stdout != want+"\n" {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}
