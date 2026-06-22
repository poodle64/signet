//go:build linux

package main

import (
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// tpmOpenDevice opens the Linux TPM resource manager (/dev/tpmrm0), falling
// back to /dev/tpm0 if the resource manager is unavailable. Returns nil, nil
// when no TPM device is present (used by the auto-detect path).
func tpmOpenDevice() (transport.TPMCloser, error) {
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(path); err == nil {
			return linuxtpm.Open(path)
		}
	}
	return nil, nil
}
