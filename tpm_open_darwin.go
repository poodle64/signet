//go:build darwin

package main

import "github.com/google/go-tpm/tpm2/transport"

// tpmOpenDevice on macOS always returns nil, nil — macOS does not expose a TPM
// resource manager. The darwin auto-detect path selects the Secure Enclave
// backend instead; this stub satisfies the signer.go call to openTPM when
// --backend tpm is forced on macOS.
func tpmOpenDevice() (transport.TPMCloser, error) {
	return nil, nil
}
