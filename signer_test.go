// signer_test.go: tests for backend selection in newSigner and autoDetectBackend.
// No hardware required; backend construction is tested without calling Enrol/Sign.
package main

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// TestNewSigner_BackendOverride_TPM verifies the tpm alias returns a *tpmSigner.
func TestNewSigner_BackendOverride_TPM(t *testing.T) {
	t.Setenv("SIGNET_BACKEND", "tpm")
	s, err := newSigner()
	if err != nil {
		t.Fatalf("newSigner(tpm): %v", err)
	}
	if _, ok := s.(*tpmSigner); !ok {
		t.Errorf("newSigner(tpm) type = %T, want *tpmSigner", s)
	}
}

// TestNewSigner_BackendOverride_PIV verifies the piv alias returns a *pivSigner.
func TestNewSigner_BackendOverride_PIV(t *testing.T) {
	t.Setenv("SIGNET_BACKEND", "piv")
	s, err := newSigner()
	if err != nil {
		t.Fatalf("newSigner(piv): %v", err)
	}
	if _, ok := s.(*pivSigner); !ok {
		t.Errorf("newSigner(piv) type = %T, want *pivSigner", s)
	}
}

// TestNewSigner_BackendOverride_SE verifies the SE aliases on darwin.
func TestNewSigner_BackendOverride_SE(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("SE backend only available on darwin (GOOS=%s)", runtime.GOOS)
	}
	for _, alias := range []string{"secure-enclave", "enclave", "se"} {
		alias := alias
		t.Run(alias, func(t *testing.T) {
			t.Setenv("SIGNET_BACKEND", alias)
			s, err := newSigner()
			if err != nil {
				t.Fatalf("newSigner(%q): %v", alias, err)
			}
			if _, ok := s.(*enclaveSigner); !ok {
				t.Errorf("newSigner(%q) type = %T, want *enclaveSigner", alias, s)
			}
		})
	}
}

// TestNewSigner_UnknownBackend verifies an unknown backend returns an error that
// names the unknown value and the valid options.
func TestNewSigner_UnknownBackend(t *testing.T) {
	cases := []string{"unknown-backend", "INVALID", "tpm2", ""}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("env=%q", tc), func(t *testing.T) {
			// Only test explicitly-unknown values; empty string triggers auto-detect.
			if tc == "" {
				t.Skip("empty string triggers auto-detect, not an error path")
			}
			t.Setenv("SIGNET_BACKEND", tc)
			_, err := newSigner()
			if err == nil {
				t.Fatalf("newSigner(%q): expected error, got nil", tc)
			}
			if !strings.Contains(err.Error(), tc) {
				t.Errorf("error %q does not mention the unknown backend %q", err, tc)
			}
			if !strings.Contains(err.Error(), "secure-enclave") {
				t.Errorf("error %q does not mention valid options", err)
			}
		})
	}
}

// TestAutoDetectBackend_GOOS verifies the platform default.
// On darwin: must return "secure-enclave".
// On linux/windows: must return "tpm" or "piv" (TPM availability is not guaranteed).
// Other platforms: must return "piv".
func TestAutoDetectBackend_GOOS(t *testing.T) {
	got := autoDetectBackend()
	switch runtime.GOOS {
	case "darwin":
		if got != "secure-enclave" {
			t.Errorf("autoDetectBackend on darwin = %q, want %q", got, "secure-enclave")
		}
	case "linux", "windows":
		if got != "tpm" && got != "piv" {
			t.Errorf("autoDetectBackend on %s = %q, want tpm or piv", runtime.GOOS, got)
		}
	default:
		if got != "piv" {
			t.Errorf("autoDetectBackend on %s = %q, want %q", runtime.GOOS, got, "piv")
		}
	}
}
