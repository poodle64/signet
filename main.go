// Command signet is a standalone hardware machine-identity CLI.
//
// signet generates and manages a non-exportable signing key sealed in the
// host's secure hardware (Apple Secure Enclave, TPM 2.0, or YubiKey PIV),
// and speaks the /v1/attest attestation protocol: it signs a broker challenge
// in hardware and exchanges the proof for a short-lived bearer token.
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
//	signet enrol   [flags] [--user-presence]
//	signet sign    [flags] <message>
//	signet auth    [flags] <broker-url>
//	signet version
//	signet doctor  [flags]
//
// Flags (enrol, sign, auth, doctor):
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
	"runtime"
)

// version is overwritten at link time by -ldflags "-X main.version=<value>".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// signerFlags registers the backend/slot/identity/agent selection flags shared by
// every signing subcommand on fs and returns pointers to their parsed values.
func signerFlags(fs *flag.FlagSet) (backend, slot, identity, agent *string) {
	backend = fs.String("backend", "", "hardware backend: secure-enclave | tpm | piv (default: auto-detect)")
	slot = fs.String("slot", "", "PIV slot: 9a | 9c | 9d | 9e | 82..95 (piv backend only; default: 9c)")
	identity = fs.String("identity", "", "Secure-Enclave key name (secure-enclave backend only; default: consumer)")
	agent = fs.String("agent", "", "path to a signet agent socket; sign/get the public key via the agent instead of local hardware")
	return
}

// selectSigner picks the signer for a signing subcommand. With --agent set, all
// signing is forwarded to the agent socket (the backend/slot/identity flags are
// the agent's concern, not the client's); otherwise a local hardware signer is
// built per the backend/slot/identity selection.
func selectSigner(backend, slot, identity, agent string) (Signer, error) {
	if agent != "" {
		return newAgentSigner(agent), nil
	}
	return newSigner(backend, slot, identity)
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printHelp()
		return nil
	}

	switch args[0] {
	case "enrol":
		fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
		backend, slot, identity, agent := signerFlags(fs)
		userPresence := fs.Bool("user-presence", false, "require Touch ID per signature (secure-enclave backend)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		signer, err := selectSigner(*backend, *slot, *identity, *agent)
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
		backend, slot, identity, agent := signerFlags(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: signet sign [flags] <message>")
		}
		signer, err := selectSigner(*backend, *slot, *identity, *agent)
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
		backend, slot, identity, agent := signerFlags(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: signet auth [flags] <broker-url>")
		}
		signer, err := selectSigner(*backend, *slot, *identity, *agent)
		if err != nil {
			return err
		}
		return cmdAuth(signer, fs.Arg(0))

	case "agent":
		fs := flag.NewFlagSet("agent", flag.ContinueOnError)
		var binds bindList
		fs.Var(&binds, "bind", "socket=slot binding, repeatable (e.g. /run/signet/bd.sock=9c)")
		backend := fs.String("backend", "piv", "hardware backend the agent owns (piv has selectable slots)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return cmdAgent(*backend, binds)

	case "version":
		fmt.Printf("signet %s %s/%s (go %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil

	case "doctor":
		fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
		// Accept the shared flags so the user can pass --identity etc. without
		// an "unknown flag" error, even though doctor probes all backends.
		_, _, _, _ = signerFlags(fs)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return cmdDoctor()

	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], helpText())
	}
}

// printHelp writes the help block to stdout and exits 0.
func printHelp() {
	fmt.Print(helpText())
}

// helpText returns the structured help block listing all subcommands.
func helpText() string {
	return `signet — hardware machine-identity CLI

Usage:
  signet <subcommand> [flags]

Subcommands:
  enrol    Generate (or recover) the hardware key and print the SPKI public key
  sign     Sign a message with the hardware key and print the base64 signature
  auth     Attest to a broker and print the Authorization header (JSON)
  agent    Own the hardware and sign on request over Unix sockets (serve mode)
  version  Print the signet version, platform, and Go runtime
  doctor   Probe each backend and report availability

Flags (enrol, sign, auth, doctor):
  --backend    secure-enclave | tpm | piv   (default: auto-detect)
  --slot       9a | 9c | 9d | 9e | 82..95  (piv backend only; default: 9c)
  --identity   <name>                       (secure-enclave only; default: consumer)
  --agent      <socket>                      (sign/enrol/auth; sign via an agent, not local hardware)
  --user-presence                           (enrol only; require Touch ID per sign)

Agent (serve mode):
  signet agent --bind <socket>=<slot> [--bind ...] [--backend piv]
    One daemon owns the token and serves a Unix socket per binding. Each socket
    is pinned to one slot; clients on it can only sign with that slot's key. The
    agent serves pubkey and sign only — it never generates a key.

`
}
