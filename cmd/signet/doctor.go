// doctor.go: 'signet doctor' — backend availability probe.
package main

import (
	"fmt"
	"runtime"

	"github.com/poodle64/signet/internal/signer"
)

// cmdDoctor probes each backend and prints a per-backend availability report.
// It is the first triage step for any hardware-identity problem.
func cmdDoctor() error {
	fmt.Printf("signet doctor — platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	probes := []struct {
		backend string
		probe   func() (bool, string)
	}{
		{"secure-enclave", signer.ProbeEnclave},
		{"tpm", signer.ProbeTPM},
		{"piv", signer.ProbePIV},
	}
	for _, p := range probes {
		ok, detail := p.probe()
		status := "UNAVAILABLE"
		if ok {
			status = "OK"
		}
		fmt.Printf("  %-18s %-14s %s\n", p.backend, status, detail)
	}

	return nil
}
