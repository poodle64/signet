// exec_e2e_test.go: end-to-end tests for 'signet exec' through the REAL
// binary. The in-process tests in exec_test.go cannot reach the success
// path — on success syscall.Exec replaces the test binary's own process
// image — so #10's core acceptance ("the child-environment assertion must
// observe the child's actual environment rather than signet's own") is
// driven here instead: the compiled signet binary runs as a subprocess
// against a fake agent socket (the newline-JSON pubkey/sign protocol from
// internal/agent, so no hardware is needed) and a fake broker, and the child
// it execs into is /usr/bin/env, whose stdout IS the child's own
// environment.
package attest

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// e2eCredBody is the two-field static credential the fake broker vends: the
// aws-mcp shape #10 was filed over, an id/secret pair a stdio MCP server
// needs both of.
const e2eCredBody = `{"name":"aws-mcp","material":{"kind":"static","fields":[` +
	`{"name":"aws_access_key_id","value":"test-key-id-value"},` +
	`{"name":"aws_secret_access_key","value":"test-secret-value"}]}}`

// e2eBroker is a fake broker that counts every attest and vend request, so
// the e2e tests can assert ONE attestation and ONE vend delivered every
// field (#10's acceptance: not N attests for N fields).
type e2eBroker struct {
	srv            *httptest.Server
	challengeCount int64
	tokenCount     int64
	credCount      int64
}

func newE2EBroker(t *testing.T) *e2eBroker {
	t.Helper()
	b := &e2eBroker{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&b.challengeCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(challengeResult{ //nolint:errcheck
			ChallengeID: "ch-e2e",
			Nonce:       "e2enonce",
			ExpiresAt:   time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/v1/attest/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&b.tokenCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResult{ //nolint:errcheck
			Key:          "e2e-bearer-key",
			KeyID:        "kid-e2e",
			Name:         "test-identity",
			ExpiresAt:    time.Now().Add(2 * time.Hour).Format(time.RFC3339),
			MaxExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&b.credCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(e2eCredBody)) //nolint:errcheck
	})
	b.srv = httptest.NewServer(mux)
	t.Cleanup(b.srv.Close)
	return b
}

// fakeAgent serves the agent socket protocol (internal/agent's wire shape)
// with a canned public key and signature, so the real signet binary can
// attest with no hardware present. It returns the socket path.
func fakeAgent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed (test cleanup)
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				var req struct {
					Op      string `json:"op"`
					Message string `json:"message"`
				}
				if err := json.NewDecoder(bufio.NewReader(c)).Decode(&req); err != nil {
					return
				}
				resp := map[string]string{}
				switch req.Op {
				case "pubkey":
					resp["public_key_der"] = stubSPKI
				case "sign":
					resp["signature_b64"] = "c3R1YnNpZw=="
				default:
					resp["error"] = "unknown op " + req.Op
				}
				b, err := json.Marshal(resp)
				if err != nil {
					return
				}
				c.Write(append(b, '\n')) //nolint:errcheck
			}(conn)
		}
	}()
	return sock
}

// buildSignetBinary compiles the real signet binary into a test-scoped
// directory. On darwin the cgo link needs the Secure Enclave Swift archive,
// which `make build`/`make test` produce before any test runs (CI does the
// same); a developer who ran bare `go test` on a mac without it gets a skip
// naming the fix, never a false failure.
func buildSignetBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "signet")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/signet")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the signet binary for the exec e2e test: %v\n%s\n(build it first: make build)", err, out)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("built binary missing at %s: %v", bin, err)
	}
	return bin
}

// runSignetExec runs the built binary as a subprocess: `signet exec` against
// the fake agent and broker, with HOME pointed at a fresh temp directory so
// the bearer cache never touches (or reads) the real ~/.signet. It returns
// the child's stdout — /usr/bin/env's printout of its OWN environment, which
// is exactly the child's actual environment the acceptance requires.
func runSignetExec(t *testing.T, bin, sock, brokerURL string, extraArgs []string) (stdout, stderr string, exitCode int) {
	t.Helper()
	args := append([]string{
		"exec", "--agent", sock, "--broker", brokerURL, "--credential", "aws-mcp",
	}, extraArgs...)
	args = append(args, "--", "/usr/bin/env")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	// Inherit the test process's environment — the child is /usr/bin/env and
	// must run — but scrub any AWS_* variables the host shell already carries,
	// or an ambient credential would false-fail the "single-field form sets
	// one variable only" assertion below. The vended values under test are
	// distinct strings, so this scrub cannot mask a real miss.
	env := make([]string, 0, len(os.Environ())+1)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "AWS_") {
			continue
		}
		env = append(env, e)
	}
	cmd.Env = append(env, "HOME="+t.TempDir())
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run signet exec: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), code
}

// TestExecE2E_MultiFieldOneAttestOneVend drives the real binary through #10's
// headline acceptance: one invocation, repeatable --field
// <logical>=<ENV_VAR> mappings, delivers BOTH fields of a two-field
// credential into the child's actual environment, with exactly ONE
// attestation and ONE vend — and without the minted bearer leaking into the
// child's environment.
func TestExecE2E_MultiFieldOneAttestOneVend(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("syscall.Exec and unix sockets are unavailable on windows; exec is unix-only in practice")
	}
	bin := buildSignetBinary(t)
	broker := newE2EBroker(t)
	sock := fakeAgent(t)

	stdout, stderr, code := runSignetExec(t, bin, sock, broker.srv.URL, []string{
		"--field", "aws_access_key_id=AWS_ACCESS_KEY_ID",
		"--field", "aws_secret_access_key=AWS_SECRET_ACCESS_KEY",
	})
	if code != 0 {
		t.Fatalf("signet exec exited %d, want 0; stderr:\n%s", code, stderr)
	}
	// /usr/bin/env's output is the CHILD's own environment: both vended
	// values must be there, proving the mapping landed in the child and not
	// merely in signet's parent-side env slice.
	if !strings.Contains(stdout, "AWS_ACCESS_KEY_ID=test-key-id-value") {
		t.Errorf("child environment lacks AWS_ACCESS_KEY_ID:\n%s", stdout)
	}
	if !strings.Contains(stdout, "AWS_SECRET_ACCESS_KEY=test-secret-value") {
		t.Errorf("child environment lacks AWS_SECRET_ACCESS_KEY:\n%s", stdout)
	}
	// One attestation (challenge + token) and one vend, not one per field.
	if got := atomic.LoadInt64(&broker.challengeCount); got != 1 {
		t.Errorf("challenge requests = %d, want 1 (one attestation for every field)", got)
	}
	if got := atomic.LoadInt64(&broker.tokenCount); got != 1 {
		t.Errorf("token requests = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&broker.credCount); got != 1 {
		t.Errorf("credential vends = %d, want 1 (one vend for every field)", got)
	}
	// The broker's bearer is signet's own credential, not the child's: it must
	// never appear in the child's environment.
	if strings.Contains(stdout, "e2e-bearer-key") {
		t.Error("the minted bearer leaked into the child's environment")
	}
}

// TestExecE2E_SingleFieldFormUnchanged pins the compatibility half of #10's
// acceptance: the original single-field form (--env-var, with the optional
// bare --field selector) sets exactly one variable and nothing else, and
// still costs one attestation and one vend.
func TestExecE2E_SingleFieldFormUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("syscall.Exec and unix sockets are unavailable on windows; exec is unix-only in practice")
	}
	bin := buildSignetBinary(t)
	broker := newE2EBroker(t)
	sock := fakeAgent(t)

	stdout, stderr, code := runSignetExec(t, bin, sock, broker.srv.URL, []string{
		"--env-var", "AWS_ACCESS_KEY_ID", "--field", "aws_access_key_id",
	})
	if code != 0 {
		t.Fatalf("signet exec exited %d, want 0; stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "AWS_ACCESS_KEY_ID=test-key-id-value") {
		t.Errorf("child environment lacks AWS_ACCESS_KEY_ID:\n%s", stdout)
	}
	if strings.Contains(stdout, "AWS_SECRET_ACCESS_KEY") {
		t.Errorf("child environment unexpectedly carries AWS_SECRET_ACCESS_KEY: the single-field form must set one variable only\n%s", stdout)
	}
	if got := atomic.LoadInt64(&broker.credCount); got != 1 {
		t.Errorf("credential vends = %d, want 1", got)
	}
}

// TestExecE2E_AbsentLogicalFieldRefused drives the real binary with a mapping
// that names a field the credential does not carry: a typed exit 6 whose
// diagnostic names the missing field and the available ones, and no child
// launched (nothing on stdout, which would have been the child's own
// protocol channel).
func TestExecE2E_AbsentLogicalFieldRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("syscall.Exec and unix sockets are unavailable on windows; exec is unix-only in practice")
	}
	bin := buildSignetBinary(t)
	broker := newE2EBroker(t)
	sock := fakeAgent(t)

	stdout, stderr, code := runSignetExec(t, bin, sock, broker.srv.URL, []string{
		"--field", "region=AWS_REGION",
	})
	if code != ExitExecUnusableMaterial {
		t.Fatalf("signet exec exited %d, want %d (unusable material); stderr:\n%s", code, ExitExecUnusableMaterial, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty (the child was never launched; stdout belongs to it)", stdout)
	}
	if !strings.Contains(stderr, "region") || !strings.Contains(stderr, "aws_access_key_id") {
		t.Errorf("stderr = %q, want it to name the missing field and the available ones", stderr)
	}
	if strings.Contains(stderr, "test-key-id-value") || strings.Contains(stderr, "test-secret-value") {
		t.Errorf("stderr = %q, leaked a field value", stderr)
	}
}
