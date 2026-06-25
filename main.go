// Command signet: hardware-rooted signing helper for Portcullis attestation.
//
// Three backends are compiled in and selected at runtime (automatically, or via
// --backend). Only the Secure Enclave backend is behind a darwin build tag; TPM
// and PIV compile on every platform.
//
//   - secure-enclave — macOS Secure Enclave via CryptoKit (Swift shim linked in
//     via cgo). Auto-selected on darwin. Works on an unsigned/ad-hoc binary: the
//     Enclave's wrapped key blob is stored in a file, not the keychain, so no
//     code-signing entitlement is required.
//
//   - tpm — TPM 2.0, pure Go via google/go-tpm. Auto-selected on linux/windows
//     when a TPM resource manager device is reachable (/dev/tpmrm0 or TBS).
//
//   - piv — YubiKey PIV, cgo against PC/SC. Fallback on all platforms. The slot
//     is selectable (--slot), so one token roots one identity per slot.
//
// Usage:
//
//	signet enrol [flags] [--user-presence]
//	signet sign  [flags] <message>
//	signet auth  [flags] <broker-url>
//
// Flags (all subcommands):
//
//	--backend   secure-enclave | tpm | piv   (default: auto-detect for the platform)
//	--slot      9a | 9c | 9d | 9e | 82..95   (piv backend only; default: 9c)
//	--identity  <name>                       (secure-enclave backend only; default: consumer)
//
// --identity names the local Secure-Enclave key blob, the way an SSH key
// filename picks one key of several, so one Mac can hold more than one identity.
// It is local-only and never sent to the broker, which resolves the identity
// from the presented public key (resolve-by-key, #73). It is ignored by the PIV
// and TPM backends, where the slot / persistent handle selects the key.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// signerFlags registers the backend/slot/identity selection flags shared by
// every subcommand on fs and returns pointers to their parsed values.
func signerFlags(fs *flag.FlagSet) (backend, slot, identity *string) {
	backend = fs.String("backend", "", "hardware backend: secure-enclave | tpm | piv (default: auto-detect)")
	slot = fs.String("slot", "", "PIV slot: 9a | 9c | 9d | 9e | 82..95 (piv backend only; default: 9c)")
	identity = fs.String("identity", "", "Secure-Enclave key name (secure-enclave backend only; default: consumer)")
	return
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}

	switch args[0] {
	case "enrol":
		fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
		backend, slot, identity := signerFlags(fs)
		userPresence := fs.Bool("user-presence", false, "require Touch ID per signature (secure-enclave backend)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		signer, err := newSigner(*backend, *slot, *identity)
		if err != nil {
			return err
		}
		spki, err := signer.Enrol(*userPresence)
		if err != nil {
			return err
		}
		fmt.Println(spki)
		return nil

	case "sign":
		fs := flag.NewFlagSet("sign", flag.ContinueOnError)
		backend, slot, identity := signerFlags(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: signet sign [flags] <message>")
		}
		signer, err := newSigner(*backend, *slot, *identity)
		if err != nil {
			return err
		}
		sig, err := signer.Sign(fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Println(sig)
		return nil

	case "auth":
		fs := flag.NewFlagSet("auth", flag.ContinueOnError)
		backend, slot, identity := signerFlags(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: signet auth [flags] <broker-url>")
		}
		signer, err := newSigner(*backend, *slot, *identity)
		if err != nil {
			return err
		}
		return cmdAuth(signer, fs.Arg(0))

	default:
		return fmt.Errorf("unknown subcommand %q; expected enrol|sign|auth\n%s", args[0], usageLine())
	}
}

func usageLine() string {
	return "usage: signet <enrol | sign <message> | auth <broker-url>> " +
		"[--backend secure-enclave|tpm|piv] [--slot 9a|9c|9d|9e|82..95] [--identity <name>] [--user-presence]"
}

func usage() error {
	return fmt.Errorf("%s", usageLine())
}
