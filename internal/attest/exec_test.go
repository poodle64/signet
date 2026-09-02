// exec_test.go: tests for the 'signet exec' subcommand.
// Reuses the stubSigner + httptest fake-broker harness from headers_test.go /
// vendtofile_test.go (headersBrokerWithCredBody, addAttestHandlers,
// rejectingBroker, captureHeadersOutput); no real hardware or network
// required.
//
// The one line that cannot be exercised here is the successful syscall.Exec
// call itself: on success it replaces the test binary's own process image,
// which would end the test process rather than let it report a result.
// Everything up to that call — attestation, vend, field resolution, argv[0]
// lookup, and env construction — is factored out and tested directly instead
// (see buildEnv below), so the untestable surface stays exactly that one
// line.
package attest

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestExec_KeyMissing verifies exit code 2 when PublicKeyDER fails (key not
// enrolled). The broker must not be contacted at all.
func TestExec_KeyMissing(t *testing.T) {
	setTempHome(t)
	s := &stubSigner{pubKeyErr: errors.New("key blob not found")}
	// Use an unreachable URL; any attempt to dial it would produce a transport
	// error that would appear as exit code 1, catching a regression.
	code, err := Exec(s, "http://127.0.0.1:0", "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"true"})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecKeyMissing {
		t.Errorf("exit code = %d, want %d (ExitExecKeyMissing)", code, ExitExecKeyMissing)
	}
}

// TestExec_AttestRejected verifies exit code 3 when the broker returns 401
// on the attestation challenge, and that the guidance line steers the reader
// local — the shared attestRejectedHint wording (the estate finding: a bare
// "broker 401" reads like a broker fault and sends the reader off diagnosing
// the wrong system).
func TestExec_AttestRejected(t *testing.T) {
	setTempHome(t)
	srv := rejectingBroker(t, http.StatusUnauthorized)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	_, stderr := captureHeadersOutput(t, func() {
		code, err = Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"true"})
	})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecAttestRejected {
		t.Errorf("exit code = %d, want %d (ExitExecAttestRejected)", code, ExitExecAttestRejected)
	}
	if !strings.Contains(stderr, "local, not an outage") {
		t.Errorf("stderr = %q, want the local-not-an-outage guidance after a broker-rejected attestation", stderr)
	}
}

// TestExec_CredOutOfScope verifies exit code 4 when the broker returns 403
// on the credential vend endpoint.
func TestExec_CredOutOfScope(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusForbidden, "")
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"true"})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecCredOutOfScope {
		t.Errorf("exit code = %d, want %d (ExitExecCredOutOfScope)", code, ExitExecCredOutOfScope)
	}
}

// TestExec_CredNotFound verifies exit code 5 when the broker returns 404 on
// the credential vend endpoint.
func TestExec_CredNotFound(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusNotFound, "")
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"true"})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecCredNotFound {
		t.Errorf("exit code = %d, want %d (ExitExecCredNotFound)", code, ExitExecCredNotFound)
	}
}

// TestExec_UnusableMaterial verifies exit code 6 for the same material shapes
// vend-to-file refuses: an ambiguous multi-field static credential with no
// --field, and (separately) an unparsable envelope. resolveField itself is
// already exhaustively tested by TestResolveField in vendtofile_test.go; this
// just pins that Exec wires the same function in on the same failure path.
func TestExec_UnusableMaterial(t *testing.T) {
	setTempHome(t)

	t.Run("ambiguous multi-field static, no --field", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SECRETA"},{"name":"b","value":"SECRETB"}]}}`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"true"})
		})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecUnusableMaterial {
			t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty on failure", stdout)
		}
		if strings.Contains(stderr, "SECRETA") || strings.Contains(stderr, "SECRETB") {
			t.Error("a field value leaked into the ambiguous-field error")
		}
	})

	t.Run("unparsable envelope", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK, `not json`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		code, err := Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"true"})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecUnusableMaterial {
			t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
		}
	})
}

// TestExec_CommandNotFound verifies exit code 7 when argv[0] cannot be
// resolved to an executable via PATH — the credential is vended successfully
// (attestation and vend both succeed) but the child is never launched, and
// the vended value must not leak into the diagnostic.
func TestExec_CommandNotFound(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"SUPERSECRETVALUE"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"signet-exec-test-definitely-not-a-real-binary"})
	})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecCommandNotFound {
		t.Errorf("exit code = %d, want %d (ExitExecCommandNotFound)", code, ExitExecCommandNotFound)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure (no partial print, and stdout belongs to the child)", stdout)
	}
	if strings.Contains(stdout, "SUPERSECRETVALUE") || strings.Contains(stderr, "SUPERSECRETVALUE") {
		t.Error("credential value leaked into exec output on a command-not-found failure")
	}
}

// TestExec_NothingOnStdoutOnSuccessPath verifies the one behavioural
// difference from headers/vend-to-file that matters most: exec must never
// write anything to stdout, even on the path that gets all the way through
// attestation, vend, and field resolution, because stdout belongs to the
// child's own protocol. It stops one step short of the actual exec (this
// drives Exec with a command that WILL be found, "true", but true is a
// real binary and calling it would replace the test process) by instead
// exercising the identical code path via a command that fails LookPath —
// covered separately in TestExec_CommandNotFound — plus the explicit
// per-failure-path stdout assertions above. This test asserts the general
// invariant directly against a failure path that gets furthest before
// bailing: unusable material, which parses the whole successful vend first.
func TestExec_NothingOnStdoutOnSuccessPath(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session"}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	stdout, _ := captureHeadersOutput(t, func() {
		code, _ = Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"true"})
	})
	if code != ExitExecUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty — exec must never print a confirmation line, unlike headers/vend-to-file", stdout)
	}
}

// TestExec_NoSecretOnStdoutOrStderr asserts that neither the vended
// credential value nor the internally minted bearer ever appears in captured
// stdout or stderr, across every failure path Exec can reach without
// actually exec-ing (the one path this package cannot drive in-process).
func TestExec_NoSecretOnStdoutOrStderr(t *testing.T) {
	setTempHome(t)

	t.Run("unusable material", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SUPERSECRETA"},{"name":"b","value":"SUPERSECRETB"}]}}`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"true"})
		})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecUnusableMaterial {
			t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
		}
		if strings.Contains(stdout, "SUPERSECRETA") || strings.Contains(stdout, "SUPERSECRETB") {
			t.Error("credential value leaked into exec stdout")
		}
		if strings.Contains(stderr, "SUPERSECRETA") || strings.Contains(stderr, "SUPERSECRETB") {
			t.Error("credential value leaked into exec stderr")
		}
	})

	t.Run("command not found", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"SUPERSECRETVALUE"}]}}`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = Exec(s, srv.URL, "my-cred", []FieldEnv{{EnvVar: "MY_TOKEN"}}, []string{"signet-exec-test-definitely-not-a-real-binary"})
		})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecCommandNotFound {
			t.Errorf("exit code = %d, want %d (ExitExecCommandNotFound)", code, ExitExecCommandNotFound)
		}
		if strings.Contains(stdout, "SUPERSECRETVALUE") || strings.Contains(stderr, "SUPERSECRETVALUE") {
			t.Error("credential value leaked into exec output")
		}
		// "verify-bearer-key" is the bearer the fake /v1/attest/token mints (see
		// addAttestHandlers, shared with verify_test.go / headers_test.go).
		if strings.Contains(stdout, "verify-bearer-key") || strings.Contains(stderr, "verify-bearer-key") {
			t.Error("minted bearer leaked into exec output")
		}
	})
}

// TestBuildEnvs exercises buildEnvs directly: the env-construction logic Exec
// relies on to set the vended value(s) in the child's environment without
// exec-ing anything, so it is fully unit-testable. The single-setting cases
// pin the semantics the original single-field form depends on; the
// multi-setting cases pin what #10 added.
func TestBuildEnvs(t *testing.T) {
	t.Run("single setting appends when absent", func(t *testing.T) {
		got := buildEnvs([]string{"PATH=/usr/bin", "HOME=/home/x"}, []envSetting{{EnvVar: "MY_TOKEN", Value: "s3cr3t"}})
		want := []string{"PATH=/usr/bin", "HOME=/home/x", "MY_TOKEN=s3cr3t"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnvs = %v, want %v", got, want)
		}
	})

	t.Run("single setting replaces a pre-existing entry rather than duplicating it", func(t *testing.T) {
		got := buildEnvs([]string{"PATH=/usr/bin", "MY_TOKEN=stale-value", "HOME=/home/x"}, []envSetting{{EnvVar: "MY_TOKEN", Value: "fresh-value"}})
		want := []string{"PATH=/usr/bin", "HOME=/home/x", "MY_TOKEN=fresh-value"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnvs = %v, want %v", got, want)
		}
		count := 0
		for _, e := range got {
			if strings.HasPrefix(e, "MY_TOKEN=") {
				count++
			}
		}
		if count != 1 {
			t.Errorf("buildEnvs result has %d entries for MY_TOKEN, want exactly 1 (no duplicate key)", count)
		}
		if strings.Contains(strings.Join(got, "\n"), "stale-value") {
			t.Error("buildEnvs left the stale value behind alongside the fresh one")
		}
	})

	t.Run("does not confuse a name that is a prefix of another name", func(t *testing.T) {
		// MY_TOKEN_EXTRA must survive a buildEnvs call targeting MY_TOKEN: a
		// naive strings.HasPrefix(e, name) without the "=" would also match
		// "MY_TOKEN_EXTRA=...".
		got := buildEnvs([]string{"MY_TOKEN_EXTRA=untouched"}, []envSetting{{EnvVar: "MY_TOKEN", Value: "fresh-value"}})
		want := []string{"MY_TOKEN_EXTRA=untouched", "MY_TOKEN=fresh-value"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnvs = %v, want %v", got, want)
		}
	})

	t.Run("multiple settings each land once, replacing stale entries", func(t *testing.T) {
		got := buildEnvs([]string{"PATH=/usr/bin", "AWS_ACCESS_KEY_ID=stale", "HOME=/home/x"},
			[]envSetting{
				{EnvVar: "AWS_ACCESS_KEY_ID", Value: "fresh-id"},
				{EnvVar: "AWS_SECRET_ACCESS_KEY", Value: "fresh-secret"},
			})
		want := []string{"PATH=/usr/bin", "HOME=/home/x", "AWS_ACCESS_KEY_ID=fresh-id", "AWS_SECRET_ACCESS_KEY=fresh-secret"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnvs = %v, want %v", got, want)
		}
		for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
			count := 0
			for _, e := range got {
				if strings.HasPrefix(e, name+"=") {
					count++
				}
			}
			if count != 1 {
				t.Errorf("buildEnvs result has %d entries for %s, want exactly 1", count, name)
			}
		}
	})

	t.Run("empty environ", func(t *testing.T) {
		got := buildEnvs(nil, []envSetting{{EnvVar: "MY_TOKEN", Value: "fresh-value"}})
		want := []string{"MY_TOKEN=fresh-value"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnvs = %v, want %v", got, want)
		}
	})
}

// TestFieldByName exercises the named-field resolution the multi-field form
// of exec relies on: exact name match on static material, access_token on
// session material, and the loud, available-fields-naming refusal for a
// logical field the credential does not carry.
func TestFieldByName(t *testing.T) {
	multi := credentialMaterial{Kind: "static", Fields: []credentialField{
		{Name: "aws_access_key_id", Value: "SECRETA"},
		{Name: "aws_secret_access_key", Value: "SECRETB"},
	}}

	t.Run("static exact match", func(t *testing.T) {
		v, err := fieldByName(multi, "aws_secret_access_key")
		if err != nil {
			t.Fatalf("fieldByName: %v", err)
		}
		if v != "SECRETB" {
			t.Errorf("fieldByName = %q, want the second field's value", v)
		}
	})

	t.Run("absent logical field names the available fields, never a value", func(t *testing.T) {
		_, err := fieldByName(multi, "region")
		if err == nil {
			t.Fatal("fieldByName: want an error for an absent field, got nil")
		}
		if !strings.Contains(err.Error(), "region") || !strings.Contains(err.Error(), "aws_access_key_id") {
			t.Errorf("error = %q, want it to name the missing field and the available ones", err.Error())
		}
		if strings.Contains(err.Error(), "SECRETA") || strings.Contains(err.Error(), "SECRETB") {
			t.Errorf("error = %q, leaked a field value", err.Error())
		}
	})

	t.Run("session access_token", func(t *testing.T) {
		v, err := fieldByName(credentialMaterial{Kind: "session", AccessToken: "livebearer"}, "access_token")
		if err != nil {
			t.Fatalf("fieldByName: %v", err)
		}
		if v != "livebearer" {
			t.Errorf("fieldByName = %q, want the access token", v)
		}
	})

	t.Run("session without an access_token is refused", func(t *testing.T) {
		_, err := fieldByName(credentialMaterial{Kind: "session"}, "access_token")
		if err == nil || !strings.Contains(err.Error(), "no access_token") {
			t.Errorf("error = %v, want the no-access_token refusal", err)
		}
	})

	t.Run("unsupported kind is refused", func(t *testing.T) {
		_, err := fieldByName(credentialMaterial{Kind: "opaque"}, "anything")
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("error = %v, want the unsupported-kind refusal", err)
		}
	})
}

// TestExec_MultiFieldMappings verifies the multi-field failure paths that can
// be driven in-process: a mapping naming a field the credential does not
// carry is a typed exit 6 whose diagnostic names the available fields and
// never a value. (The success path — every mapped variable set in the CHILD's
// actual environment, one attestation, one vend — cannot run in-process
// because syscall.Exec would replace the test binary; that is what
// exec_e2e_test.go drives with the real binary.)
func TestExec_MultiFieldMappings(t *testing.T) {
	setTempHome(t)

	t.Run("absent logical field is exit 6 and names the gap", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"aws-mcp","material":{"kind":"static","fields":[{"name":"aws_access_key_id","value":"SECRETA"},{"name":"aws_secret_access_key","value":"SECRETB"}]}}`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = Exec(s, srv.URL, "aws-mcp", []FieldEnv{
				{Field: "aws_access_key_id", EnvVar: "AWS_ACCESS_KEY_ID"},
				{Field: "region", EnvVar: "AWS_REGION"},
			}, []string{"true"})
		})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecUnusableMaterial {
			t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty on failure", stdout)
		}
		if !strings.Contains(stderr, "region") || !strings.Contains(stderr, "aws_secret_access_key") {
			t.Errorf("stderr = %q, want it to name the missing field and the available ones", stderr)
		}
		if strings.Contains(stderr, "SECRETA") || strings.Contains(stderr, "SECRETB") {
			t.Errorf("stderr = %q, leaked a field value", stderr)
		}
	})

	t.Run("session mapping to access_token resolves", func(t *testing.T) {
		// Resolution succeeds here; the run then stops only at the exec step,
		// which is unreachable in-process — so drive it with a command that
		// fails LookPath and pin that resolution got PAST the field step (the
		// failure is command-not-found, exit 7, not unusable material, 6).
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"sess","material":{"kind":"session","access_token":"livebearer"}}`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		code, err := Exec(s, srv.URL, "sess", []FieldEnv{
			{Field: "access_token", EnvVar: "SESSION_TOKEN"},
		}, []string{"signet-exec-test-definitely-not-a-real-binary"})
		if err != nil {
			t.Fatalf("Exec: unexpected error: %v", err)
		}
		if code != ExitExecCommandNotFound {
			t.Errorf("exit code = %d, want %d (field resolution must succeed; the run stops at LookPath)", code, ExitExecCommandNotFound)
		}
	})
}

// equalStringSlices compares two string slices by content and order.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
