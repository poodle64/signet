// Command signet: hardware-rooted signing helper for Portcullis attestation.
//
// Three backends are compiled in and selected at runtime (automatically or via
// SIGNET_BACKEND). Only the Secure Enclave backend is behind a darwin
// build tag; TPM and PIV compile on every platform.
//
//   - secure-enclave — macOS Secure Enclave via CryptoKit (Swift shim linked in
//     via cgo). Auto-selected on darwin. Works on an unsigned/ad-hoc binary: the
//     Enclave's wrapped key blob is stored in a file, not the keychain, so no
//     code-signing entitlement is required.
//
//   - tpm — TPM 2.0, pure Go via google/go-tpm. Auto-selected on linux/windows
//     when a TPM resource manager device is reachable (/dev/tpmrm0 or TBS).
//
//   - piv — YubiKey PIV slot 9c, cgo against PC/SC. Fallback on all platforms.
//
// Usage:
//
//	signet enrol [--user-presence]
//	signet sign <message>
//	signet auth <broker-url>
//
// Environment variables:
//
//	SIGNET_BACKEND  secure-enclave | tpm | piv  (auto-detected if unset)
//	SIGNET_IDENTITY names which local keypair to sign as (the SE key-blob), the
//	                way an SSH key filename picks one key of several. One name maps
//	                to one key blob and so one public key, letting one Mac hold more
//	                than one identity; without it every consumer on a box would share
//	                one key. The name is local-only and never sent to the broker,
//	                which resolves the identity from the presented public key
//	                (resolve-by-key, #73). (default: "consumer")
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	subcommand := args[0]

	switch subcommand {
	case "enrol":
		userPresence := false
		for _, a := range args[1:] {
			if a == "--user-presence" {
				userPresence = true
			}
		}
		signer, err := newSigner()
		if err != nil {
			return err
		}
		spki, err := signer.Enrol(userPresence)
		if err != nil {
			return err
		}
		fmt.Println(spki)
		return nil

	case "sign":
		if len(args) < 2 {
			return fmt.Errorf("usage: signet sign <message>")
		}
		signer, err := newSigner()
		if err != nil {
			return err
		}
		sig, err := signer.Sign(args[1])
		if err != nil {
			return err
		}
		fmt.Println(sig)
		return nil

	case "auth":
		if len(args) < 2 {
			return fmt.Errorf("usage: signet auth <broker-url>")
		}
		signer, err := newSigner()
		if err != nil {
			return err
		}
		return cmdAuth(signer, args[1])

	default:
		return fmt.Errorf("unknown subcommand %q; expected enrol|sign|auth\n%s", subcommand, usageLine())
	}
}

func usageLine() string {
	return "usage: signet <enrol [--user-presence] | sign <message> | auth <broker-url>>"
}

func usage() error {
	return fmt.Errorf("%s", usageLine())
}
