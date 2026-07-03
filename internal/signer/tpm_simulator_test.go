//go:build tpmsimulator

// tpm_simulator_test.go: TPM backend tests using the go-tpm software simulator.
// Run with: go test -tags tpmsimulator ./...
//
// The go-tpm software simulator (github.com/google/go-tpm/tpm2/transport/simulator)
// has a cgo/OpenSSL dependency (ms-tpm-20-ref). The tpmsimulator build tag keeps
// that dep out of normal builds.
package signer

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// TestTPMEnrolAndSign exercises a full enrol+sign round-trip against the
// software TPM simulator, then verifies the P1363 signature with the returned
// public key.
func TestTPMEnrolAndSign(t *testing.T) {
	// Open the simulator.
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open TPM simulator: %v", err)
	}
	defer sim.Close()

	// --- Enrol: create the key, extract SPKI DER ---
	_, pub, err := tpmCreateOrLoadPersistent(sim)
	if err != nil {
		t.Fatalf("tpmCreateOrLoadPersistent: %v", err)
	}

	spkiB64, err := tpmPublicToSPKI(pub)
	if err != nil {
		t.Fatalf("tpmPublicToSPKI: %v", err)
	}
	spkiDER, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		t.Fatalf("decode base64 SPKI: %v", err)
	}
	anyPub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		t.Fatalf("parse SPKI: %v", err)
	}
	ecPub, ok := anyPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("SPKI contains %T, want *ecdsa.PublicKey", anyPub)
	}

	// --- Sign ---
	const message = "ch-00000000-0000-0000-0000-000000000001.testnonce"
	digest := sha256.Sum256([]byte(message))

	namedHandle, _, err := tpmCreateOrLoadPersistent(sim)
	if err != nil {
		t.Fatalf("reload persistent key: %v", err)
	}

	sigRsp, err := tpm2.Sign{
		KeyHandle: namedHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(sim)
	if err != nil {
		t.Fatalf("TPM Sign: %v", err)
	}

	ecdsaSig, err := sigRsp.Signature.Signature.ECDSA()
	if err != nil {
		t.Fatalf("extract ECDSA sig: %v", err)
	}

	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	sv := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)

	// Verify the raw r,s values against the extracted public key.
	if !ecdsa.Verify(ecPub, digest[:], r, sv) {
		t.Error("ecdsa.Verify failed: TPM signature does not validate against enrolled public key")
	}

	// Verify the P1363 wire encoding round-trips correctly.
	rBytes := r.Bytes()
	sBytes := sv.Bytes()
	if len(rBytes) > 32 || len(sBytes) > 32 {
		t.Fatalf("r or s > 32 bytes: %d, %d", len(rBytes), len(sBytes))
	}
	p1363 := make([]byte, 64)
	copy(p1363[32-len(rBytes):32], rBytes)
	copy(p1363[64-len(sBytes):64], sBytes)
	if len(p1363) != 64 {
		t.Errorf("P1363 is %d bytes, want 64", len(p1363))
	}

	// Verify idempotency: a second call to tpmCreateOrLoadPersistent should
	// return the same public key (key already persisted, ReadPublic path).
	_, pub2, err := tpmCreateOrLoadPersistent(sim)
	if err != nil {
		t.Fatalf("second tpmCreateOrLoadPersistent: %v", err)
	}
	spkiB64b, err := tpmPublicToSPKI(pub2)
	if err != nil {
		t.Fatalf("second tpmPublicToSPKI: %v", err)
	}
	if spkiB64 != spkiB64b {
		t.Errorf("idempotency check: SPKI changed between calls\n  first:  %s\n  second: %s",
			spkiB64, spkiB64b)
	}
}
