// signer_piv.go: YubiKey PIV backend for signet.
//
// Uses github.com/go-piv/piv-go/v2/piv (cgo, requires PC/SC). Operates on
// slot 9c (Digital Signature, piv.SlotSignature) with an EC P-256 key.
//
// Enrol: generates a new key if the slot is empty (keyed by GenerateKey with
// the default management key), or reads the existing public key otherwise.
//
// Sign: SHA-256 digests the message, calls the slot's crypto.Signer, and
// converts the DER output to the broker's P1363 r||s wire format.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

// pivSigner signs with the first detected YubiKey using the PIV application.
type pivSigner struct{}

// openFirstYubiKey opens the first YubiKey listed by piv.Cards().
func openFirstYubiKey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("PIV: list smart cards: %w", err)
	}
	if len(cards) == 0 {
		return nil, fmt.Errorf("PIV: no smart cards (YubiKeys) found")
	}
	yk, err := piv.Open(cards[0])
	if err != nil {
		return nil, fmt.Errorf("PIV: open %q: %w", cards[0], err)
	}
	return yk, nil
}

// pivPublicKey returns the existing P-256 public key in slot 9c, or nil if the
// slot holds no key (or a non-EC key). It reads the KEY itself — via KeyInfo
// (firmware >= 5.3.0), falling back to the attestation certificate's key — and
// deliberately does NOT read the slot's stored X.509 certificate object.
// GenerateKey persists only the keypair and never writes a certificate, so a
// Certificate() probe always misses a freshly enrolled key: that made Enrol
// re-generate (clobbering the key) on every call, and Sign/PublicKeyDER report
// an empty slot. Errors are swallowed so the caller falls through to GenerateKey
// only when the slot is genuinely empty.
func pivPublicKey(yk *piv.YubiKey) *ecdsa.PublicKey {
	if info, err := yk.KeyInfo(piv.SlotSignature); err == nil {
		if pub, ok := info.PublicKey.(*ecdsa.PublicKey); ok {
			return pub
		}
	}
	// Fallback for firmware < 5.3.0 (no KeyInfo): the attestation certificate
	// carries the slot's public key. Both paths read the live key, never a
	// stored certificate, so a present key is always rediscovered.
	if cert, err := yk.Attest(piv.SlotSignature); err == nil && cert != nil {
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return pub
		}
	}
	return nil
}

func (s *pivSigner) Enrol(_ bool) (string, error) {
	yk, err := openFirstYubiKey()
	if err != nil {
		return "", err
	}
	defer yk.Close()

	// Try to read an existing key first (idempotent).
	if existing := pivPublicKey(yk); existing != nil {
		spki, err := x509.MarshalPKIXPublicKey(existing)
		if err != nil {
			return "", fmt.Errorf("PIV: marshal existing SPKI: %w", err)
		}
		return base64.StdEncoding.EncodeToString(spki), nil
	}

	// No existing key — generate one.
	pub, err := yk.GenerateKey(
		piv.DefaultManagementKey,
		piv.SlotSignature,
		piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			PINPolicy:   piv.PINPolicyNever,
			TouchPolicy: piv.TouchPolicyNever,
		},
	)
	if err != nil {
		return "", fmt.Errorf("PIV: GenerateKey (slot 9c): %w", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("PIV: generated key is not ECDSA (unexpected type %T)", pub)
	}
	spki, err := x509.MarshalPKIXPublicKey(ecPub)
	if err != nil {
		return "", fmt.Errorf("PIV: marshal SPKI: %w", err)
	}
	return base64.StdEncoding.EncodeToString(spki), nil
}

// PublicKeyDER returns the enrolled public key as base64-encoded SPKI DER
// without generating a new key. Returns an error when no key is enrolled in
// slot 9c.
func (s *pivSigner) PublicKeyDER() (string, error) {
	yk, err := openFirstYubiKey()
	if err != nil {
		return "", err
	}
	defer yk.Close()

	pub := pivPublicKey(yk)
	if pub == nil {
		return "", fmt.Errorf("PIV: no key in slot 9c; run 'signet enrol' first")
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("PIV: marshal SPKI: %w", err)
	}
	return base64.StdEncoding.EncodeToString(spki), nil
}

func (s *pivSigner) Sign(message string) (string, error) {
	yk, err := openFirstYubiKey()
	if err != nil {
		return "", err
	}
	defer yk.Close()

	// Retrieve the existing public key to pass to PrivateKey.
	pub := pivPublicKey(yk)
	if pub == nil {
		return "", fmt.Errorf("PIV: no key in slot 9c; run 'signet enrol' first")
	}

	// Obtain the crypto.Signer backed by the YubiKey.
	priv, err := yk.PrivateKey(piv.SlotSignature, pub, piv.KeyAuth{})
	if err != nil {
		return "", fmt.Errorf("PIV: get private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("PIV: private key does not implement crypto.Signer")
	}

	digest := sha256.Sum256([]byte(message))

	// The PIV ECDSA signer returns a DER-encoded SEQUENCE{r, s}.
	der, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("PIV: sign: %w", err)
	}

	p1363, err := derToP1363(der)
	if err != nil {
		return "", fmt.Errorf("PIV: convert DER to P1363: %w", err)
	}
	return base64.StdEncoding.EncodeToString(p1363), nil
}
