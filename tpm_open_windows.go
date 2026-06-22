//go:build windows

package main

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// tpmOpenDevice opens the Windows TBS (Trusted Platform Module Base Services)
// interface. Returns nil, nil when TBS is unavailable (no TPM on this host).
func tpmOpenDevice() (transport.TPMCloser, error) {
	t, err := windowstpm.Open()
	if err != nil {
		// Treat open failure as "no TPM available" so the auto-detect path
		// falls through to the PIV backend.
		return nil, nil
	}
	return t, nil
}
