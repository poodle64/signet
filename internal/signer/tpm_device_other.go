//go:build !linux && !windows && !darwin

package signer

import (
	"github.com/google/go-tpm/tpm2/transport"
)

// tpmOpenDevice on platforms other than Linux and Windows always returns nil,
// nil — no TPM resource manager path is known, so the auto-detect path falls
// through to the PIV backend.
func tpmOpenDevice() (transport.TPMCloser, error) {
	return nil, nil
}
