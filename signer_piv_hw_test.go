// signer_piv_hw_test.go: hardware round-trip test for the PIV (YubiKey) backend.
//
// Unlike signer_test.go (backend selection only, no hardware), this exercises a
// real enrol -> sign -> verify cycle against a physically present YubiKey. It is
// gated behind SIGNET_PIV_HW_TEST=1 so the normal `go test` run (and CI without
// a token) skips it. It is the regression guard for the slot-9c persistence bug:
// pivPublicKey read the slot's X.509 certificate (never written by GenerateKey)
// instead of the key, so every Enrol re-generated a fresh key and Sign reported
// an empty slot. The decisive assertion is that two consecutive Enrol calls
// return the SAME SPKI.
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"os"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

func TestPIV_HW_EnrolStable_SignVerify(t *testing.T) {
	if os.Getenv("SIGNET_PIV_HW_TEST") != "1" {
		t.Skip("set SIGNET_PIV_HW_TEST=1 with a YubiKey present to run the PIV hardware round-trip")
	}

	s := &pivSigner{slot: piv.SlotSignature, label: "9c"}

	// Enrol must be idempotent: a key already in the slot is read back, not
	// regenerated. Two calls returning different SPKI is exactly the persistence
	// regression this test guards.
	first, err := s.Enrol(false)
	if err != nil {
		t.Fatalf("first enrol: %v", err)
	}
	second, err := s.Enrol(false)
	if err != nil {
		t.Fatalf("second enrol: %v", err)
	}
	if first != second {
		t.Fatalf("enrol not idempotent: two calls returned different SPKI\n first=%s\nsecond=%s\n"+
			"(pivPublicKey must read the slot KEY via KeyInfo/Attest, never a stored certificate)", first, second)
	}

	// PublicKeyDER (the no-generate read path Sign relies on) must agree.
	pk, err := s.PublicKeyDER()
	if err != nil {
		t.Fatalf("PublicKeyDER: %v", err)
	}
	if pk != first {
		t.Fatalf("PublicKeyDER %s != enrol %s", pk, first)
	}

	// Sign and verify a canonical attestation message against the enrolled key.
	msg := "challenge-id.nonce"
	sigB64, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("P1363 signature length = %d, want 64 (r||s for P-256)", len(sig))
	}

	der, err := base64.StdEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("decode SPKI: %v", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parse SPKI: %v", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("enrolled key is not ECDSA (%T)", pubAny)
	}
	digest := sha256.Sum256([]byte(msg))
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, ss) {
		t.Fatal("ecdsa.Verify failed for the YubiKey PIV signature")
	}
}

// TestPIV_HW_MultiSlot_DistinctStableKeys verifies --slot roots a
// distinct, stable identity per slot on one token: slots 9c and 9a enrol
// different keys, and each stays stable after the other is touched. This is the
// regression guard for the multi-identity-per-YubiKey feature — one slot is one
// public key is one broker identity.
func TestPIV_HW_MultiSlot_DistinctStableKeys(t *testing.T) {
	if os.Getenv("SIGNET_PIV_HW_TEST") != "1" {
		t.Skip("set SIGNET_PIV_HW_TEST=1 with a YubiKey present to run the PIV hardware round-trip")
	}

	sig9c := &pivSigner{slot: piv.SlotSignature, label: "9c"}
	sig9a := &pivSigner{slot: piv.SlotAuthentication, label: "9a"}

	k9c, err := sig9c.Enrol(false)
	if err != nil {
		t.Fatalf("enrol 9c: %v", err)
	}
	k9a, err := sig9a.Enrol(false)
	if err != nil {
		t.Fatalf("enrol 9a: %v", err)
	}
	if k9c == k9a {
		t.Fatal("slots 9c and 9a returned the SAME key; each slot must hold an independent keypair")
	}

	// Each slot stays stable and independent after the other was touched.
	if again, err := sig9c.Enrol(false); err != nil || again != k9c {
		t.Fatalf("slot 9c not stable after touching 9a: err=%v changed=%v", err, again != k9c)
	}
}
