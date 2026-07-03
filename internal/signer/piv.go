// piv.go: YubiKey PIV backend for signet.
//
// Uses github.com/go-piv/piv-go/v2/piv (cgo, requires PC/SC). Operates on a
// configurable PIV slot (--slot; default 9c, Digital Signature) with
// an EC P-256 key. Selecting a different slot per identity lets ONE YubiKey
// root MULTIPLE distinct signet identities: the broker resolves each identity
// by its public key, and one key per slot is one public key is one identity.
//
// Enrol: generates a new key if the slot is empty (keyed by GenerateKey with
// the default management key), or reads the existing public key otherwise.
//
// Sign: SHA-256 digests the message, calls the slot's crypto.Signer, and
// converts the DER output to the broker's P1363 r||s wire format.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
)

// pivSigner signs with the first detected YubiKey using the PIV application,
// on the slot selected at construction from the --slot flag.
type pivSigner struct {
	slot  piv.Slot
	label string // human label for the slot, used only in error messages
}

// newPIVSigner resolves the PIV slot name and returns a signer.
func newPIVSigner(slot string) (*pivSigner, error) {
	s, label, err := pivSlot(slot)
	if err != nil {
		return nil, err
	}
	return &pivSigner{slot: s, label: label}, nil
}

// pivSlot maps a slot name to a PIV slot. Empty defaults to 9c (Digital
// Signature). Accepts the four named PIV slots (9a, 9c, 9d, 9e) and the retired
// key-management slots 82..95 (hex) — giving one YubiKey up to ~24
// independently-enrollable slots, hence up to ~24 distinct signet identities on
// a single token (one per slot).
func pivSlot(slot string) (piv.Slot, string, error) {
	raw := strings.TrimSpace(slot)
	switch strings.ToLower(raw) {
	case "", "9c":
		return piv.SlotSignature, "9c", nil
	case "9a":
		return piv.SlotAuthentication, "9a", nil
	case "9d":
		return piv.SlotKeyManagement, "9d", nil
	case "9e":
		return piv.SlotCardAuthentication, "9e", nil
	}
	// Retired key-management slots 0x82..0x95 (20 extra usable slots).
	if n, err := strconv.ParseUint(raw, 16, 32); err == nil {
		if slot, ok := piv.RetiredKeyManagementSlot(uint32(n)); ok {
			return slot, strings.ToLower(raw), nil
		}
	}
	return piv.Slot{}, "", fmt.Errorf(
		"invalid PIV slot %q (--slot); expected 9a | 9c | 9d | 9e or a retired slot 82..95 (hex)",
		raw,
	)
}

// pivCards returns the list of PC/SC smart card reader names visible to the OS.
// Used by the doctor subcommand and by openFirstYubiKey.
func pivCards() ([]string, error) {
	return piv.Cards()
}

// openFirstYubiKey opens the first YubiKey listed by piv.Cards().
func openFirstYubiKey() (*piv.YubiKey, error) {
	cards, err := pivCards()
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

// pivPublicKey returns the existing P-256 public key in the given slot, or nil
// if the slot holds no key (or a non-EC key). It reads the KEY itself — via
// KeyInfo (firmware >= 5.3.0), falling back to the attestation certificate's
// key — and deliberately does NOT read the slot's stored X.509 certificate
// object. GenerateKey persists only the keypair and never writes a certificate,
// so a Certificate() probe always misses a freshly enrolled key: that made
// Enrol re-generate (clobbering the key) on every call, and Sign/PublicKeyDER
// report an empty slot. Errors are swallowed so the caller falls through to
// GenerateKey only when the slot is genuinely empty.
func pivPublicKey(yk *piv.YubiKey, slot piv.Slot) *ecdsa.PublicKey {
	if info, err := yk.KeyInfo(slot); err == nil {
		if pub, ok := info.PublicKey.(*ecdsa.PublicKey); ok {
			return pub
		}
	}
	// Fallback for firmware < 5.3.0 (no KeyInfo): the attestation certificate
	// carries the slot's public key. Both paths read the live key, never a
	// stored certificate, so a present key is always rediscovered.
	if cert, err := yk.Attest(slot); err == nil && cert != nil {
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
	if existing := pivPublicKey(yk, s.slot); existing != nil {
		spki, err := x509.MarshalPKIXPublicKey(existing)
		if err != nil {
			return "", fmt.Errorf("PIV: marshal existing SPKI: %w", err)
		}
		return base64.StdEncoding.EncodeToString(spki), nil
	}

	// No existing key — generate one.
	pub, err := yk.GenerateKey(
		piv.DefaultManagementKey,
		s.slot,
		piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			PINPolicy:   piv.PINPolicyNever,
			TouchPolicy: piv.TouchPolicyNever,
		},
	)
	if err != nil {
		return "", fmt.Errorf("PIV: GenerateKey (slot %s): %w", s.label, err)
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
// the configured slot.
func (s *pivSigner) PublicKeyDER() (string, error) {
	yk, err := openFirstYubiKey()
	if err != nil {
		return "", err
	}
	defer yk.Close()

	pub := pivPublicKey(yk, s.slot)
	if pub == nil {
		return "", fmt.Errorf("PIV: no key in slot %s; run 'signet enrol' first", s.label)
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
	pub := pivPublicKey(yk, s.slot)
	if pub == nil {
		return "", fmt.Errorf("PIV: no key in slot %s; run 'signet enrol' first", s.label)
	}

	// Obtain the crypto.Signer backed by the YubiKey.
	priv, err := yk.PrivateKey(s.slot, pub, piv.KeyAuth{})
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
