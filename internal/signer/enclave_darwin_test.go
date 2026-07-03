//go:build darwin

// enclave_darwin_test.go: darwin-only backend-selection tests. The
// *enclaveSigner type exists only behind the darwin build tag, so the type
// assertion below cannot live in the platform-neutral signer_test.go.
package signer

import "testing"

// TestNew_BackendOverride_SE verifies all three Secure Enclave aliases
// resolve to the enclave signer.
func TestNew_BackendOverride_SE(t *testing.T) {
	for _, alias := range []string{"secure-enclave", "enclave", "se"} {
		t.Run(alias, func(t *testing.T) {
			s, err := New(alias, "", "")
			if err != nil {
				t.Fatalf("New(%q): %v", alias, err)
			}
			if _, ok := s.(*enclaveSigner); !ok {
				t.Errorf("New(%q) type = %T, want *enclaveSigner", alias, s)
			}
		})
	}
}
