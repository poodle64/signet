//go:build !darwin

// signer_enclave_other.go: non-darwin stub for the Secure Enclave backend.
//
// The real Secure Enclave signer (signer_darwin.go) links a CryptoKit Swift shim
// via cgo and exists only on macOS. signer.go's backend switch references
// newEnclaveSigner unconditionally, so every target platform must provide the
// symbol to compile. Off darwin we supply a stub: autoDetectBackend never selects
// secure-enclave on a non-darwin host (it picks tpm or piv), so this path is
// reached only when SIGNET_BACKEND is explicitly forced to
// secure-enclave there — in which case it fails at use with a clear message rather
// than failing the build for every Linux/Windows consumer.
package main

import "fmt"

func newEnclaveSigner() Signer { return enclaveUnavailable{} }

type enclaveUnavailable struct{}

func (enclaveUnavailable) Enrol(userPresence bool) (string, error) {
	return "", fmt.Errorf("the secure-enclave backend is only available on macOS; use tpm or piv")
}

func (enclaveUnavailable) Sign(message string) (string, error) {
	return "", fmt.Errorf("the secure-enclave backend is only available on macOS; use tpm or piv")
}
