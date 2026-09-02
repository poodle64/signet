// exec.go: 'signet exec' — the cmd-layer flag parsing and dispatch for
// attest.Exec. Mirrors runHeaders/runVendToFile's shape; the one addition is
// splitting os.Args on the "--" terminator that separates signet's own
// flags from the child command's, since flag.FlagSet consumes "--" silently
// (it stops parsing there) and offers no way to tell afterwards whether it
// was present at all.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/poodle64/signet/internal/attest"
)

// fieldList is the repeatable --field collector. A value containing "=" is
// the multi-field mapping form (<logical>=<ENV_VAR>, repeatable, sets each
// named field); a value without "=" is the single-field selector form (the
// original --field <name>, paired with --env-var). The two forms are
// mutually exclusive — see runExec.
type fieldList []string

func (f *fieldList) String() string { return strings.Join(*f, ",") }

func (f *fieldList) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// runExec parses exec's flags and calls attest.Exec, returning the typed
// exit code. It is separate from run() so typed exits never conflict with
// run()'s single error/exit-1 contract.
//
// On success attest.Exec never returns — the process image is replaced by
// the child — so a return from runExec, of any kind, is always a failure.
func runExec(args []string) int {
	// Split args on the first literal "--" ourselves, before fs.Parse ever
	// sees them: flag.FlagSet treats "--" as the flag terminator and simply
	// drops it, so by the time Parse returns there is no way to distinguish
	// "the user wrote --" from "the user wrote nothing at all". Everything
	// after "--" is the child's argv and must never be interpreted as a
	// signet flag.
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	flagArgs := args
	if sepIdx >= 0 {
		flagArgs = args[:sepIdx]
	}

	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.Usage = execUsage
	backend, slot, identity, agentSock := signerFlags(fs)
	broker := fs.String("broker", "", "broker URL (required)")
	cred := fs.String("credential", "", "credential name to vend (required)")
	envVar := fs.String("env-var", "", "environment variable name to set on the child process (single-field form; required unless --field <logical>=<ENV_VAR> mappings are given)")
	var fields fieldList
	fs.Var(&fields, "field", "either <name> (single-field form: which field --env-var carries) or repeatable <logical>=<ENV_VAR> mappings (multi-field form: one env var per field, one attestation and one vend for all of them)")

	// -h/--help works even without a "--", so `signet exec --help` behaves
	// like every other subcommand.
	help, err := parseArgs(fs, flagArgs)
	if help {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if sepIdx < 0 {
		fmt.Fprintln(os.Stderr, "error: signet exec: missing -- separator (usage: signet exec [flags] -- <command> [args...])")
		return 1
	}
	childArgv := args[sepIdx+1:]
	if len(childArgv) == 0 {
		fmt.Fprintln(os.Stderr, "error: signet exec: a command is required after -- (usage: signet exec [flags] -- <command> [args...])")
		return 1
	}
	if *broker == "" {
		fmt.Fprintln(os.Stderr, "error: signet exec: --broker is required")
		return 1
	}
	if *cred == "" {
		fmt.Fprintln(os.Stderr, "error: signet exec: --credential is required")
		return 1
	}

	// Classify the --field values into the two forms. A value containing "="
	// is a mapping; any other value is the single-field selector. Mixing the
	// two is ambiguous (which env var would the bare name land in?), so it is
	// refused rather than guessed at.
	mappings := 0
	selectors := 0
	for _, v := range fields {
		if strings.Contains(v, "=") {
			mappings++
		} else {
			selectors++
		}
	}
	if mappings > 0 && selectors > 0 {
		fmt.Fprintln(os.Stderr, "error: signet exec: --field takes either <name> (with --env-var) or <logical>=<ENV_VAR> mappings, not both")
		return 1
	}
	if selectors > 1 {
		fmt.Fprintln(os.Stderr, "error: signet exec: --field <name> may be given at most once with --env-var; use repeatable --field <logical>=<ENV_VAR> mappings to set several variables")
		return 1
	}

	var fieldEnvs []attest.FieldEnv
	if mappings > 0 {
		// Multi-field form: each --field is <logical>=<ENV_VAR>. --env-var has
		// no meaning here (the mapping names the variable), so an explicitly
		// set --env-var is refused rather than silently ignored — the same
		// stance headers takes with --header + --bare.
		if isFlagSet(fs, "env-var") {
			fmt.Fprintln(os.Stderr, "error: signet exec: --env-var cannot be combined with --field <logical>=<ENV_VAR> mappings (the mapping names the variable); drop --env-var, or use the single-field form --env-var <NAME> [--field <name>]")
			return 1
		}
		seenLogical := map[string]bool{}
		seenEnvVar := map[string]bool{}
		for _, v := range fields {
			logical, env, ok := strings.Cut(v, "=")
			if !ok || logical == "" || env == "" {
				fmt.Fprintf(os.Stderr, "error: signet exec: --field %q is not a <logical>=<ENV_VAR> mapping (both sides must be non-empty)\n", v)
				return 1
			}
			if strings.Contains(env, "=") {
				fmt.Fprintf(os.Stderr, "error: signet exec: --field %q has an invalid environment variable name %q\n", v, env)
				return 1
			}
			if seenLogical[logical] {
				fmt.Fprintf(os.Stderr, "error: signet exec: --field maps logical field %q more than once\n", logical)
				return 1
			}
			if seenEnvVar[env] {
				fmt.Fprintf(os.Stderr, "error: signet exec: --field maps environment variable %q more than once\n", env)
				return 1
			}
			seenLogical[logical] = true
			seenEnvVar[env] = true
			fieldEnvs = append(fieldEnvs, attest.FieldEnv{Field: logical, EnvVar: env})
		}
	} else {
		// Single-field form, unchanged: --env-var required, one optional
		// --field <name> selector.
		if *envVar == "" {
			fmt.Fprintln(os.Stderr, "error: signet exec: --env-var is required (or use repeatable --field <logical>=<ENV_VAR> mappings to deliver several fields)")
			return 1
		}
		selector := ""
		if selectors == 1 {
			selector = fields[0]
		}
		fieldEnvs = []attest.FieldEnv{{Field: selector, EnvVar: *envVar}}
	}

	s, err := selectSigner(*backend, *slot, *identity, *agentSock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	// attest.Exec reports every failure on stderr; do not repeat the error
	// here, or failures would print twice.
	code, _ := attest.Exec(s, *broker, *cred, fieldEnvs, childArgv)
	return code
}

// execHelpBody returns the `exec` flag, usage, and exit-code reference. It is
// the ONE copy, the same pattern headersHelpBody() established: helpText()
// embeds it for `signet --help`, and runExec installs execUsage as the
// FlagSet's Usage for `signet exec --help`, so the two cannot drift.
func execHelpBody() string {
	return `Exec flags:
  signet exec [flags] --broker <url> --credential <name> {--env-var <NAME> [--field <name>] | --field <logical>=<ENV_VAR> [...]} -- <command> [args...]
  --broker      <url>    broker URL (required)
  --credential  <name>   credential name to vend (required)
  --env-var     <NAME>   environment variable to set on the child (single-field
                          form; required unless --field mappings are given)
  --field       <name>   single-field form: which field --env-var carries
                          (required when the credential has more than one
                          static field; ignored for session material, which
                          always sets access_token)
  --field       <logical>=<ENV_VAR>   multi-field form, repeatable: one env var
                          per logical field, one attestation and one vend for
                          all of them (e.g. --field aws_access_key_id=AWS_ACCESS_KEY_ID
                          --field aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

The "--" separates signet's own flags from the child command's; everything
after it is passed to <command> untouched, never parsed by signet.

exec vends the credential, sets the mapped value(s) in the CHILD's
environment only (never signet's own, never a shell variable, never a file),
and replaces this process with <command> via syscall.Exec — the same
process-image-replacement primitive git and ssh-agent style helpers use, so
there is no signet parent process left holding the value in memory and no
extra hop in the child's stdio. Nothing is printed to stdout on success:
stdout belongs to <command>, which is typically about to speak a protocol
(e.g. MCP stdio) on it.

A multi-field credential (an id/secret pair — AWS, Backblaze, most vendors)
is delivered in ONE invocation with repeatable --field <logical>=<ENV_VAR>
mappings: one attestation, one vend, every variable set. Nesting exec inside
exec (one per field) attests once per field and is the workaround this
replaces.

Example — launch a stdio MCP server with a broker-vended token in its
environment, without the token ever touching this shell:

  signet exec --broker https://broker.example.internal --credential github-pat \
    --env-var GITHUB_PERSONAL_ACCESS_TOKEN -- github-mcp-server stdio

Example — deliver a two-field credential in one invocation:

  signet exec --broker https://broker.example.internal --credential aws-mcp \
    --field aws_access_key_id=AWS_ACCESS_KEY_ID \
    --field aws_secret_access_key=AWS_SECRET_ACCESS_KEY \
    -- aws-mcp-server stdio

Exec exit codes:
  0  success — never actually returned; syscall.Exec replaces this process
  2  key missing — no key enrolled for this identity
  3  attestation rejected — broker refused the attestation
  4  credential out of scope — identity exists but credential is not in its scope
  5  credential not found — credential name absent from the catalogue
  6  unusable material — a mapped field cannot be resolved from the vended
     credential (absent logical field, ambiguous single-field resolution, or
     an unsupported material kind)
  7  command not found — <command> could not be resolved to an executable on PATH

`
}

// execUsage is the FlagSet Usage for `signet exec`. flag prints Usage on
// -h/--help and then returns ErrHelp, so without this the subcommand's help
// is only flag's own bare list of flags — never the "--" contract or the
// worked example a caller needs before wiring this into a real command.
func execUsage() {
	fmt.Fprint(os.Stderr, `signet exec — attest, vend a credential, set it as an env var, and exec a command

Usage:
  signet exec [flags] --broker <url> --credential <name> --env-var <NAME> -- <command> [args...]

`+execHelpBody()+`Backend selection flags (--backend, --slot, --identity, --agent): signet --help
`)
}
