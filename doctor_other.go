//go:build !darwin

// doctor_other.go: Secure Enclave stub for non-darwin platforms.
package main

// checkSE reports SE unavailable on non-darwin platforms (no Swift shim linked).
func checkSE() {
	reportFail("secure-enclave", "macOS only")
}
