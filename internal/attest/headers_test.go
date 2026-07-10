// headers_test.go: tests for the 'signet headers' vend-to-headers helper.
// Mirrors verify_test.go's fake-broker pattern; no real hardware or network required.
package attest

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// headersBrokerWithCredBody builds a fake broker that serves the attestation
// endpoints plus GET /v1/credentials/{name} returning credStatus with body.
func headersBrokerWithCredBody(t *testing.T, credStatus int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	addAttestHandlers(t, mux)
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(credStatus)
		if body != "" {
			w.Write([]byte(body)) //nolint:errcheck
		}
	})
	return httptest.NewServer(mux)
}

// captureHeadersOutput runs f with both os.Stdout and os.Stderr redirected to
// pipes and returns everything written to each. Headers writes its result via
// fmt.Println (stdout) and every diagnostic via fmt.Fprintf(os.Stderr, ...),
// so this is the only way to assert on both channels.
func captureHeadersOutput(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe (stdout): %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe (stderr): %v", err)
	}
	os.Stdout = outW
	os.Stderr = errW
	f()
	outW.Close()
	errW.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr
	outBytes, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	errBytes, err := io.ReadAll(errR)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(outBytes), string(errBytes)
}

// TestHeaders_Success verifies exit code 0, the exact compact-JSON stdout
// line (default header "Authorization", default format "bearer"), and a
// silent stderr.
func TestHeaders_Success(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"topsecretvalue123"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := `{"Authorization":"Bearer topsecretvalue123"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty on success", stderr)
	}
}

// TestHeaders_HeaderOverride verifies --header renames the emitted JSON key.
func TestHeaders_HeaderOverride(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"apikeyvalue"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, _ := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "X-Api-Key", "bearer")
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := `{"X-Api-Key":"Bearer apikeyvalue"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// TestHeaders_FormatRaw verifies --format raw omits the "Bearer " prefix.
func TestHeaders_FormatRaw(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"rawvalue123"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, _ := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "raw")
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := `{"Authorization":"rawvalue123"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// TestHeaders_SessionKindRefused verifies exit code 6 when the vended
// credential is `session` material, which headers cannot turn into a single
// static header value.
func TestHeaders_SessionKindRefused(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session","access_token":"livebearer"}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
}

// TestHeaders_MultiFieldRefused verifies exit code 6 when static material
// carries more than one field (headers cannot pick one on the caller's behalf).
func TestHeaders_MultiFieldRefused(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SECRETA"},{"name":"b","value":"SECRETB"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
}

// TestHeaders_ZeroFieldsRefused verifies exit code 6 when static material
// carries zero fields.
func TestHeaders_ZeroFieldsRefused(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
}

// TestHeaders_UnparsableEnvelope verifies exit code 6 when the broker's 200
// body is not valid JSON.
func TestHeaders_UnparsableEnvelope(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK, `not json`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
}

// TestHeaders_CredOutOfScope verifies exit code 4 when the broker returns 403
// on the credential vend endpoint.
func TestHeaders_CredOutOfScope(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusForbidden, "")
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersCredOutOfScope {
		t.Errorf("exit code = %d, want %d (ExitHeadersCredOutOfScope)", code, ExitHeadersCredOutOfScope)
	}
}

// TestHeaders_CredNotFound verifies exit code 5 when the broker returns 404
// on the credential vend endpoint.
func TestHeaders_CredNotFound(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusNotFound, "")
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersCredNotFound {
		t.Errorf("exit code = %d, want %d (ExitHeadersCredNotFound)", code, ExitHeadersCredNotFound)
	}
}

// TestHeaders_KeyMissing verifies exit code 2 when PublicKeyDER fails (key
// not enrolled). The broker must not be contacted at all.
func TestHeaders_KeyMissing(t *testing.T) {
	setTempHome(t)
	s := &stubSigner{pubKeyErr: errors.New("key blob not found")}
	// Use an unreachable URL; any attempt to dial it would produce a transport
	// error that would appear as exit code 1, catching a regression.
	code, err := Headers(s, "http://127.0.0.1:0", "my-cred", "Authorization", "bearer")
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersKeyMissing {
		t.Errorf("exit code = %d, want %d (ExitHeadersKeyMissing)", code, ExitHeadersKeyMissing)
	}
}

// TestHeaders_AttestRejected verifies exit code 3 when the broker returns 401
// on the attestation challenge (resolves to a broker-rejection, not transport).
func TestHeaders_AttestRejected(t *testing.T) {
	setTempHome(t)
	srv := rejectingBroker(t, http.StatusUnauthorized)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersAttestRejected {
		t.Errorf("exit code = %d, want %d (ExitHeadersAttestRejected)", code, ExitHeadersAttestRejected)
	}
}

// TestHeaders_NoSecretInStderr asserts that neither the vended credential
// value nor the internally minted bearer ever appears on stderr. headers
// deliberately prints the credential value to STDOUT (that is its entire
// purpose), but every diagnostic and failure path must stay silent about it.
func TestHeaders_NoSecretInStderr(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session","access_token":"SUPERSECRETSESSIONVALUE"}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer")
	})
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure (no partial print)", stdout)
	}
	if strings.Contains(stderr, "SUPERSECRETSESSIONVALUE") {
		t.Error("credential value leaked into headers stderr")
	}
	// "verify-bearer-key" is the bearer the fake /v1/attest/token mints (see
	// addAttestHandlers, shared with verify_test.go) — used only as the
	// Authorization header when calling the broker; it must never appear in
	// headers' own output.
	if strings.Contains(stderr, "verify-bearer-key") {
		t.Error("minted bearer leaked into headers stderr")
	}
}
