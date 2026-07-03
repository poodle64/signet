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
//	signet verify  [flags] --broker <url> [--credential <name>]
//	signet agent   --bind <socket>=<slot> [--bind ...] [--backend piv]
//	signet version
//	signet doctor  [flags]
//
// Flags (enrol, sign, auth, verify, doctor):
//
//	--backend   secure-enclave | tpm | piv   (default: auto-detect for the platform)
//	--slot      9a | 9c | 9d | 9e | 82..95   (piv backend only; default: 9c)
//	--identity  <name>                       (secure-enclave backend only; default: consumer)
//	--agent     <socket>                     (sign via a signet agent socket, not local hardware)
//	--user-presence                          (enrol only; require Touch ID per signature)
//
// --identity names the local Secure-Enclave key blob, the way an SSH key
// filename picks one key of several, so one Mac can hold more than one identity.
// It is local-only and never sent to the broker, which resolves the identity
// from the presented public key (resolve-by-key). It is ignored by the PIV
// and TPM backends, where the slot / persistent handle selects the key.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/poodle64/signet/internal/agent"
	"github.com/poodle64/signet/internal/attest"
	"github.com/poodle64/signet/internal/signer"
)

// version is overwritten at link time by -ldflags "-X main.version=<value>".
var version = "dev"

func main() {
	// 'verify' is handled here rather than in run() because it needs typed exit
	// codes (2–5) that cannot be expressed as errors and still give os.Exit(1).
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		os.Exit(runVerify(os.Args[2:]))
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// runVerify parses verify's flags and calls attest.Verify, returning the typed
// exit code. It is separate from run() so typed exits never conflict with
// run()'s single error/exit-1 contract.
func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	backend, slot, identity, agentSock := signerFlags(fs)
	broker := fs.String("broker", "", "broker URL (required)")
	cred := fs.String("credential", "", "credential name to probe (optional)")
	help, err := parseArgs(fs, args)
	if help {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if *broker == "" {
		fmt.Fprintln(os.Stderr, "error: signet verify: --broker is required")
		return 1
	}
	s, err := selectSigner(*backend, *slot, *identity, *agentSock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// attest.Verify reports every failure on its own output; do not repeat the
	// error on stderr here, or transport failures would print twice.
	code, _ := attest.Verify(s, *broker, *cred)
	return code
}

// parseArgs parses args with fs, treating -h/--help as success: the flag
// package has already printed the flag list to stderr, so the caller should
// simply exit 0 rather than wrapping flag.ErrHelp in an "error:" line.
func parseArgs(fs *flag.FlagSet, args []string) (help bool, err error) {
	err = fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		return true, nil
	}
	return false, err
}

// signerFlags registers the backend/slot/identity/agent selection flags shared by
// every signing subcommand on fs and returns pointers to their parsed values.
func signerFlags(fs *flag.FlagSet) (backend, slot, identity, agentSock *string) {
	backend = fs.String("backend", "", "hardware backend: secure-enclave | tpm | piv (default: auto-detect)")
	slot = fs.String("slot", "", "PIV slot: 9a | 9c | 9d | 9e | 82..95 (piv backend only; default: 9c)")
	identity = fs.String("identity", "", "Secure-Enclave key name (secure-enclave backend only; default: consumer)")
	agentSock = fs.String("agent", "", "path to a signet agent socket; sign/get the public key via the agent instead of local hardware")
	return
}

// selectSigner picks the signer for a signing subcommand. With --agent set, all
// signing is forwarded to the agent socket (the backend/slot/identity flags are
// the agent's concern, not the client's); otherwise a local hardware signer is
// built per the backend/slot/identity selection.
func selectSigner(backend, slot, identity, agentSock string) (signer.Signer, error) {
	if agentSock != "" {
		return agent.NewClient(agentSock), nil
	}
	return signer.New(backend, slot, identity)
}

// bindList collects repeatable --bind <socket>=<slot> values.
type bindList []string

func (b *bindList) String() string { return strings.Join(*b, ",") }

func (b *bindList) Set(v string) error {
	*b = append(*b, v)
	return nil
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printHelp()
		return nil
	}

	switch args[0] {
	case "enrol":
		fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
		backend, slot, identity, agentSock := signerFlags(fs)
		userPresence := fs.Bool("user-presence", false, "require Touch ID per signature (enrol only; secure-enclave backend)")
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		s, err := selectSigner(*backend, *slot, *identity, *agentSock)
		if err != nil {
			return err
		}
		spki, err := s.Enrol(*userPresence)
		if err != nil {
			return err
		}
		fmt.Println(spki)
		return nil

	case "sign":
		fs := flag.NewFlagSet("sign", flag.ContinueOnError)
		backend, slot, identity, agentSock := signerFlags(fs)
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("signet sign: a message argument is required (signet sign [flags] <message>)")
		}
		s, err := selectSigner(*backend, *slot, *identity, *agentSock)
		if err != nil {
			return err
		}
		sig, err := s.Sign(fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Println(sig)
		return nil

	case "auth":
		fs := flag.NewFlagSet("auth", flag.ContinueOnError)
		backend, slot, identity, agentSock := signerFlags(fs)
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("signet auth: a broker URL argument is required (signet auth [flags] <broker-url>)")
		}
		s, err := selectSigner(*backend, *slot, *identity, *agentSock)
		if err != nil {
			return err
		}
		return attest.Auth(s, fs.Arg(0))

	case "agent":
		fs := flag.NewFlagSet("agent", flag.ContinueOnError)
		var binds bindList
		fs.Var(&binds, "bind", "socket=slot binding, repeatable (e.g. /run/signet/bd.sock=9c)")
		backend := fs.String("backend", "piv", "hardware backend the agent owns (piv has selectable slots)")
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		return agent.Run(*backend, binds)

	case "version":
		// runtime.Version() already carries the "go" prefix (e.g. go1.25.10).
		fmt.Printf("signet %s %s/%s (%s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil

	case "doctor":
		fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
		// Accept the shared flags so a command line built for another subcommand
		// can be replayed against doctor; --backend narrows the probe to one
		// backend, the rest are meaningless here and ignored.
		backend, _, _, _ := signerFlags(fs)
		help, err := parseArgs(fs, args[1:])
		if help {
			return nil
		}
		if err != nil {
			return err
		}
		return cmdDoctor(*backend)

	case "verify":
		// Reached only if someone calls run("verify", ...) directly (e.g. in tests
		// that go through run()). In practice main() short-circuits verify before
		// run() is called, so this branch exists only for completeness.
		return fmt.Errorf("use 'signet verify' directly; typed exit codes require os.Exit")

	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], helpText())
	}
}

// printHelp writes the help block to stdout.
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
  verify   Consumer pre-flight: attest and optionally probe a credential vend
  agent    Own the hardware and sign on request over Unix sockets (serve mode)
  version  Print the signet version, platform, and Go runtime
  doctor   Probe each backend and report availability (--backend probes one)

Flags (enrol, sign, auth, verify, doctor):
  --backend    secure-enclave | tpm | piv   (default: auto-detect)
  --slot       9a | 9c | 9d | 9e | 82..95   (piv only; 82..95 are hex retired slots; default: 9c)
  --identity   <name>                       (secure-enclave only; default: consumer)
  --agent      <socket>                     (sign via a signet agent socket, not local hardware)
  --user-presence                           (enrol only; require Touch ID per signature; secure-enclave only)

Verify flags:
  --broker     <url>    broker URL (required)
  --credential <name>   credential name to probe vend scope (optional)

Verify exit codes:
  0  success — attestation accepted; credential resolvable (if --credential given)
  2  key missing — no key enrolled for this identity
  3  attestation rejected — broker refused the attestation
  4  credential out of scope — identity exists but credential is not in its scope
  5  credential not found — credential name absent from the catalogue

Agent (serve mode):
  signet agent --bind <socket>=<slot> [--bind ...] [--backend piv]
    One daemon owns the token and serves a Unix socket per binding. Each socket
    is pinned to one slot; clients on it can only sign with that slot's key. The
    agent serves pubkey and sign only — it never generates a key.

`
}
