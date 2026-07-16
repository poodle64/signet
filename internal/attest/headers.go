// headers.go: 'signet headers' — the vend-to-headers helper for Claude Code's
// .mcp.json `headersHelper` contract. It composes the same attestation leg as
// Auth with the same credential-vend leg as Verify, then extracts a single
// static field and prints it as one compact-JSON HTTP header line.
package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/poodle64/signet/internal/signer"
)

// Typed exit codes for signet headers. The first five values match Verify's
// vocabulary exactly (this command performs the same attest-then-vend round
// trip); ExitHeadersUnusableMaterial is the one code specific to headers,
// covering the extra "turn the material into a single header value" step
// verify never has to take.
const (
	// ExitHeadersOK is success: the header line was printed to stdout.
	ExitHeadersOK = 0
	// ExitHeadersKeyMissing means no key is enrolled for this identity.
	ExitHeadersKeyMissing = 2
	// ExitHeadersAttestRejected means the broker refused the attestation (401/4xx).
	ExitHeadersAttestRejected = 3
	// ExitHeadersCredOutOfScope means the identity exists but the credential is
	// not in its vend scope (broker returned 403).
	ExitHeadersCredOutOfScope = 4
	// ExitHeadersCredNotFound means the credential name does not exist in the
	// catalogue (broker returned 404).
	ExitHeadersCredNotFound = 5
	// ExitHeadersUnusableMaterial means the vended credential cannot become a
	// single header value: its material is not `static`, its envelope did not
	// parse, or its static fields number zero or more than one.
	ExitHeadersUnusableMaterial = 6
)

// Headers is the vend-to-headers entry point. It:
//  1. Confirms a key is enrolled (PublicKeyDER succeeds).
//  2. Runs the attestation round-trip via attestFresh.
//  3. Vends credName via GET /v1/credentials/{credName} with the minted bearer.
//  4. Requires the result to be `static` material with exactly one field, and
//     prints {"<headerName>":"<value>"} (format "raw") or
//     {"<headerName>":"Bearer <value>"} (format "bearer", the default) as the
//     ONLY line written to stdout.
//
// Every diagnostic — including every failure path — goes to stderr, and never
// carries the credential value or the minted bearer: on failure the message
// names only the failure class (key missing, broker rejection, out of scope,
// not found, or the shape of the unusable material), never a secret.
//
// It returns a typed exit code and a human-readable error for failures. A nil
// error with a non-zero code means the check was conclusive and the caller
// should exit with that code. A non-nil error with exit code 1 is an
// unexpected transport or encoding failure.
func Headers(s signer.Signer, brokerURL, credName, headerName, format string) (exitCode int, err error) {
	// Step 1: confirm a key is enrolled.
	_, keyErr := s.PublicKeyDER()
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "signet headers: no key enrolled: %v\n", keyErr)
		return ExitHeadersKeyMissing, nil
	}

	// Step 2: attestation round-trip.
	bc, attestErr := attestFresh(s, brokerURL)
	if attestErr != nil {
		// Distinguish a broker rejection (a non-2xx HTTP response, carried as a
		// *BrokerError anywhere in the wrap chain) from a transport error.
		var be *BrokerError
		if errors.As(attestErr, &be) {
			fmt.Fprintf(os.Stderr, "signet headers: broker rejected attestation: %v\n", attestErr)
			return ExitHeadersAttestRejected, nil
		}
		fmt.Fprintf(os.Stderr, "signet headers: unexpected error: %v\n", attestErr)
		return 1, attestErr
	}

	// Step 3: vend the credential.
	endpoint := strings.TrimRight(brokerURL, "/") + "/v1/credentials/" + url.PathEscape(credName)
	status, body, getErr := brokerGet(endpoint, bc.Key)
	if getErr != nil {
		fmt.Fprintf(os.Stderr, "signet headers: network error: %v\n", getErr)
		return 1, getErr
	}
	switch {
	case status == http.StatusForbidden:
		fmt.Fprintf(os.Stderr, "signet headers: credential %q out of scope for this identity (403)\n", credName)
		return ExitHeadersCredOutOfScope, nil
	case status == http.StatusNotFound:
		fmt.Fprintf(os.Stderr, "signet headers: credential %q not found in catalogue (404)\n", credName)
		return ExitHeadersCredNotFound, nil
	case status < 200 || status >= 300:
		fmt.Fprintf(os.Stderr, "signet headers: unexpected broker %d vending credential %q\n", status, credName)
		return 1, fmt.Errorf("unexpected broker %d on credential vend", status)
	}

	// Step 4: the material must be a single-field static value.
	var env credentialEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		fmt.Fprintf(os.Stderr, "signet headers: credential %q: unusable material (envelope did not parse)\n", credName)
		return ExitHeadersUnusableMaterial, nil
	}
	if env.Material.Kind != "static" {
		fmt.Fprintf(os.Stderr, "signet headers: credential %q: unusable material (kind %q, want static)\n", credName, env.Material.Kind)
		return ExitHeadersUnusableMaterial, nil
	}
	if len(env.Material.Fields) != 1 {
		fmt.Fprintf(os.Stderr, "signet headers: credential %q: unusable material (%d static fields, want exactly 1)\n", credName, len(env.Material.Fields))
		return ExitHeadersUnusableMaterial, nil
	}
	value := env.Material.Fields[0].Value

	// Step 5: format and print — the only line written to stdout.
	headerValue := value
	if format == "bearer" {
		headerValue = "Bearer " + value
	}
	out, marshalErr := json.Marshal(map[string]string{headerName: headerValue})
	if marshalErr != nil {
		fmt.Fprintf(os.Stderr, "signet headers: encode output: %v\n", marshalErr)
		return 1, marshalErr
	}
	fmt.Println(string(out))
	return ExitHeadersOK, nil
}
