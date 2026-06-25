// signer.go: backend selector and Signer interface.
//
// Three backends are compiled in; selection is at runtime (SIGNET_BACKEND
// or autoDetectBackend). Only the Secure Enclave backend is behind a darwin build
// tag (it links a Swift shim via cgo); TPM and PIV compile on every platform.
//
//   - secure-enclave: macOS Secure Enclave via CryptoKit (a small Swift shim
//     linked into this binary by cgo). Auto-selected on darwin. Works on an
//     unsigned/ad-hoc binary: the Enclave's wrapped key blob is stored in a file,
//     not the keychain, so no code-signing entitlement is required.
//
//   - tpm: TPM 2.0 via github.com/google/go-tpm (pure Go). Auto-selected on
//     Linux and Windows when a TPM resource manager device is reachable.
//
//   - piv: YubiKey PIV, cgo against PC/SC. Auto-selected as the fallback on any
//     platform when no higher-priority backend is available. The slot is
//     configurable (SIGNET_PIV_SLOT, default 9c), so one token can root
//     multiple identities — one per slot.
//
// Backend selection:
//
//	SIGNET_BACKEND   secure-enclave | tpm | piv (overrides auto-detect)
//	SIGNET_PIV_SLOT  9a | 9c | 9d | 9e | 82..95 (piv backend only; default 9c)
package main

import (
	"fmt"
	"os"
	"runtime"
)

// Signer is a hardware-rooted signer: it can publish its public key (Enrol),
// return the public key without side effects (PublicKeyDER), and sign a
// message (Sign). All three return the broker's wire encodings.
//
//   - Enrol returns SPKI DER (base64-encoded); idempotent — existing key is
//     never clobbered.
//   - PublicKeyDER returns the same SPKI DER without generating a new key;
//     returns an error if no key has been enrolled yet.
//   - Sign returns the IEEE P1363 r||s ECDSA-P256 signature over SHA256(message)
//     (base64-encoded).
type Signer interface {
	Enrol(userPresence bool) (string, error)
	PublicKeyDER() (string, error)
	Sign(message string) (string, error)
}

// newSigner selects a backend. SIGNET_BACKEND overrides auto-detect.
// Auto-detect order: darwin → secure-enclave; linux/windows → tpm (if device
// reachable) then piv; other → piv.
func newSigner() (Signer, error) {
	backend := os.Getenv("SIGNET_BACKEND")
	if backend == "" {
		backend = autoDetectBackend()
	}
	switch backend {
	case "secure-enclave", "enclave", "se":
		return newEnclaveSigner(), nil
	case "tpm":
		return &tpmSigner{}, nil
	case "piv":
		return newPivSigner()
	default:
		return nil, fmt.Errorf(
			"unknown SIGNET_BACKEND %q; expected secure-enclave | tpm | piv",
			backend,
		)
	}
}

// autoDetectBackend returns the backend name for the current platform.
func autoDetectBackend() string {
	switch runtime.GOOS {
	case "darwin":
		return "secure-enclave"
	case "linux", "windows":
		// Probe for a TPM device; fall back to PIV if none is found.
		t, err := openTPM()
		if err == nil && t != nil {
			t.Close()
			return "tpm"
		}
		return "piv"
	default:
		return "piv"
	}
}
