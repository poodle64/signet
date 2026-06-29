// verify.go: 'signet verify' — consumer pre-flight with typed exit codes.
//
// signet verify performs the attestation round-trip (and, optionally, a
// scoped credential vend) against a broker, then exits with a typed code so
// callers can branch on the exact failure mode rather than treating every
// problem as a single opaque "unauthorised".
//
// Exit codes:
//
//	0  success — attestation accepted; credential resolvable (if --credential given)
//	2  key missing — no key enrolled for this identity
//	3  attestation rejected — broker refused the attestation (HTTP 401/4xx)
//	4  credential out of scope — broker accepted the attestation but the named
//	   credential is not in this identity's vend scope (HTTP 403)
//	5  credential not found — broker accepted the attestation but the named
//	   credential does not exist in the catalogue (HTTP 404)
package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Typed exit codes for signet verify. Each maps to a distinct failure mode so
// callers can branch without parsing human-readable text.
const (
	// ExitVerifyOK is success: attestation accepted; credential resolvable if asked.
	ExitVerifyOK = 0
	// ExitVerifyKeyMissing means no key is enrolled for this identity.
	ExitVerifyKeyMissing = 2
	// ExitVerifyAttestRejected means the broker refused the attestation (401/4xx).
	ExitVerifyAttestRejected = 3
	// ExitVerifyCredOutOfScope means the identity exists but the credential is
	// not in its vend scope (broker returned 403).
	ExitVerifyCredOutOfScope = 4
	// ExitVerifyCredNotFound means the credential name does not exist in the
	// catalogue (broker returned 404).
	ExitVerifyCredNotFound = 5
)

// brokerGet sends a GET request to endpoint authenticated with bearerKey and
// returns the HTTP status code and response body. It does not decode JSON
// because the credential leg only needs the status code to classify the result.
func brokerGet(endpoint, bearerKey string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	if bearerKey != "" {
		req.Header.Set("Authorization", "Bearer "+bearerKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// cmdVerify performs the consumer pre-flight check. It:
//  1. Confirms a key is enrolled (PublicKeyDER succeeds).
//  2. Runs the attestation round-trip via attestFresh.
//  3. If credName is non-empty, probes GET /v1/credentials/{credName} with the
//     minted bearer and classifies the response.
//
// It returns a typed exit code and a human-readable error for failures. A nil
// error with a non-zero code means the check was conclusive (the summary line
// was printed) and the caller should exit with that code. A non-nil error with
// exit code 1 is an unexpected transport or argument failure.
func cmdVerify(signer Signer, brokerURL, credName string) (exitCode int, err error) {
	fmt.Printf("signet verify — broker: %s\n\n", brokerURL)

	// Step 1: confirm a key is enrolled.
	_, keyErr := signer.PublicKeyDER()
	if keyErr != nil {
		fmt.Printf("  key              FAIL           no key enrolled: %v\n", keyErr)
		return ExitVerifyKeyMissing, nil
	}
	fmt.Printf("  key              OK             key present\n")

	// Step 2: attestation round-trip.
	bc, attestErr := attestFresh(signer, brokerURL)
	if attestErr != nil {
		// Distinguish a broker rejection from a transport error.
		// attestFresh wraps errUnauthorized from brokerPost, and non-2xx as
		// "broker <status>: <body>". Either signals a rejection; a network
		// error is a different class.
		if errors.Is(attestErr, errUnauthorized) || isAttestRejection(attestErr) {
			fmt.Printf("  attest           FAIL           broker rejected attestation: %v\n", attestErr)
			return ExitVerifyAttestRejected, nil
		}
		// Transport or unexpected error: propagate so the caller sees exit 1.
		fmt.Printf("  attest           FAIL           unexpected error: %v\n", attestErr)
		return 1, attestErr
	}
	fmt.Printf("  attest           OK             bearer minted\n")

	if credName == "" {
		fmt.Printf("\nresult: OK\n")
		return ExitVerifyOK, nil
	}

	// Step 3: probe the credential vend endpoint.
	endpoint := strings.TrimRight(brokerURL, "/") + "/v1/credentials/" + credName
	status, body, getErr := brokerGet(endpoint, bc.Key)
	if getErr != nil {
		fmt.Printf("  credential       FAIL           network error: %v\n", getErr)
		return 1, getErr
	}
	switch {
	case status >= 200 && status < 300:
		fmt.Printf("  credential %-16s OK             resolvable\n", credName)
		fmt.Printf("\nresult: OK\n")
		return ExitVerifyOK, nil
	case status == http.StatusForbidden:
		fmt.Printf("  credential %-16s FAIL           out of scope for this identity (403)\n", credName)
		return ExitVerifyCredOutOfScope, nil
	case status == http.StatusNotFound:
		fmt.Printf("  credential %-16s FAIL           not found in catalogue (404)\n", credName)
		return ExitVerifyCredNotFound, nil
	default:
		detail := strings.TrimSpace(string(body))
		fmt.Printf("  credential %-16s FAIL           unexpected broker %d: %s\n", credName, status, detail)
		return 1, fmt.Errorf("unexpected broker %d on credential vend", status)
	}
}

// isAttestRejection reports whether err looks like a broker-side rejection
// from attestFresh (i.e. a non-2xx HTTP response, wrapped as "broker <N>: …").
// This avoids importing a typed error for attest rejection; the "broker " prefix
// is the one stable shape that brokerPost emits for non-2xx responses.
func isAttestRejection(err error) bool {
	return strings.HasPrefix(err.Error(), "attest/challenge: broker ") ||
		strings.HasPrefix(err.Error(), "attest/token: broker ")
}
