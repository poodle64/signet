// probe.go: backend availability probes for 'signet doctor'.
//
// Each probe answers "is this backend usable on this host right now?" with a
// human-readable detail line. The Secure Enclave probe is platform-split
// (probeEnclave in enclave_darwin.go / enclave_stub.go) because it needs the
// cgo shim on macOS.
package signer

import "fmt"

// ProbeEnclave reports whether the Secure Enclave backend is usable.
func ProbeEnclave() (ok bool, detail string) {
	return probeEnclave()
}

// ProbeTPM reports whether a TPM device is reachable.
func ProbeTPM() (ok bool, detail string) {
	t, err := openTPM()
	if err != nil {
		return false, fmt.Sprintf("open failed: %v", err)
	}
	if t == nil {
		return false, "no TPM device found (/dev/tpmrm0, /dev/tpm0, or TBS)"
	}
	t.Close()
	return true, "TPM device opened successfully"
}

// ProbePIV reports whether any PC/SC smart card (YubiKey) is visible.
func ProbePIV() (ok bool, detail string) {
	cards, err := pivCards()
	if err != nil {
		return false, fmt.Sprintf("list smart cards failed: %v", err)
	}
	if len(cards) == 0 {
		return false, "no smart cards / YubiKeys detected"
	}
	return true, fmt.Sprintf("%d card(s) detected: %v", len(cards), cards)
}
