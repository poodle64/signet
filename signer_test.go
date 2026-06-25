// signer_test.go: tests for backend selection in newSigner and autoDetectBackend.
// No hardware required; backend construction is tested without calling Enrol/Sign.
package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestNewSigner_BackendOverride_TPM verifies the tpm name returns a *tpmSigner.
func TestNewSigner_BackendOverride_TPM(t *testing.T) {
	s, err := newSigner("tpm", "", "")
	if err != nil {
		t.Fatalf("newSigner(tpm): %v", err)
	}
	if _, ok := s.(*tpmSigner); !ok {
		t.Errorf("newSigner(tpm) type = %T, want *tpmSigner", s)
	}
}

// TestNewSigner_BackendOverride_PIV verifies the piv name returns a *pivSigner
// (slot construction only; no hardware touched).
func TestNewSigner_BackendOverride_PIV(t *testing.T) {
	s, err := newSigner("piv", "", "")
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
			s, err := newSigner(alias, "", "")
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
// names the unknown value and the valid options. An empty backend is not tested
// here: it triggers auto-detect, not an error.
func TestNewSigner_UnknownBackend(t *testing.T) {
	for _, tc := range []string{"unknown-backend", "INVALID", "tpm2"} {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			_, err := newSigner(tc, "", "")
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
