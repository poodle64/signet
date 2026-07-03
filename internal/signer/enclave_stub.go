//go:build !darwin

// enclave_stub.go: non-darwin stub for the Secure Enclave backend.
//
// The real Secure Enclave signer (enclave_darwin.go) links a CryptoKit Swift
// shim via cgo and exists only on macOS. New's backend switch references
// newEnclaveSigner unconditionally, so every target platform must provide the
// symbol to compile. Off darwin we supply a stub: autoDetect never selects
// secure-enclave on a non-darwin host (it picks tpm or piv), so this path is
// reached only when the backend is explicitly forced to secure-enclave there —
// in which case it fails at use with a clear message rather than failing the
// build for every Linux/Windows consumer. The identity argument is ignored.
package signer

import "fmt"

func newEnclaveSigner(_ string) Signer { return enclaveUnavailable{} }

// probeEnclave is the doctor probe for the Secure Enclave backend.
func probeEnclave() (bool, string) {
	return false, "macOS only"
}

type enclaveUnavailable struct{}

func (enclaveUnavailable) Enrol(userPresence bool) (string, error) {
	return "", fmt.Errorf("the secure-enclave backend is only available on macOS; use tpm or piv")
}

func (enclaveUnavailable) PublicKeyDER() (string, error) {
	return "", fmt.Errorf("the secure-enclave backend is only available on macOS; use tpm or piv")
}

func (enclaveUnavailable) Sign(message string) (string, error) {
	return "", fmt.Errorf("the secure-enclave backend is only available on macOS; use tpm or piv")
}
