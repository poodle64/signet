// doctor.go: 'signet doctor' — backend availability probe.
package main

import (
	"fmt"
	"runtime"
)

// cmdDoctor probes each backend and prints a per-backend availability report.
// It is the first triage step for any hardware-identity problem.
func cmdDoctor() error {
	fmt.Printf("signet doctor — platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	checkSE()
	checkTPM()
	checkPIV()

	return nil
}

// checkTPM probes the TPM backend by attempting to open the device.
func checkTPM() {
	t, err := openTPM()
	if err != nil {
		reportFail("tpm", fmt.Sprintf("open failed: %v", err))
		return
	}
	if t == nil {
		reportFail("tpm", "no TPM device found (/dev/tpmrm0, /dev/tpm0, or TBS)")
		return
	}
	t.Close()
	reportOK("tpm", "TPM device opened successfully")
}

// checkPIV probes the PIV backend by listing smart cards.
func checkPIV() {
	cards, err := pivCards()
	if err != nil {
		reportFail("piv", fmt.Sprintf("list smart cards failed: %v", err))
		return
	}
	if len(cards) == 0 {
		reportFail("piv", "no smart cards / YubiKeys detected")
		return
	}
	reportOK("piv", fmt.Sprintf("%d card(s) detected: %v", len(cards), cards))
}

// ok/fail helpers keep the output format consistent.
func reportOK(backend, detail string) {
	fmt.Printf("  %-18s OK             %s\n", backend, detail)
}

func reportFail(backend, detail string) {
	fmt.Printf("  %-18s UNAVAILABLE    %s\n", backend, detail)
}
