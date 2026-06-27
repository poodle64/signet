//go:build darwin

// doctor_darwin.go: Secure Enclave availability probe for 'signet doctor'.
package main

/*
#include <stdint.h>
int signet_se_available(void);
*/
import "C"

// checkSE probes the Secure Enclave via the CryptoKit shim.
func checkSE() {
	if C.signet_se_available() != 0 {
		reportOK("secure-enclave", "CryptoKit reports Secure Enclave present")
	} else {
		reportFail("secure-enclave", "CryptoKit reports no Secure Enclave (needs Apple Silicon or T2)")
	}
}
