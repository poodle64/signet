// tpm.go: TPM 2.0 backend for signet.
//
// Uses the google/go-tpm tpm2 package (pure Go). Creates and persists an
// ECDSA P-256 signing key at fixed persistent handle 0x81010001 (in the
// owner-hierarchy user range). Idempotent: if a key already exists at that
// handle it is reused without modification.
//
// Device paths:
//   - Linux:   /dev/tpmrm0 (resource manager) or /dev/tpm0 (fallback)
//   - Windows: TBS (Trusted Platform Module Base Services)
//   - Other:   no device known; backend unavailable (auto-detect falls through)
package signer

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// tpmPersistentHandle is the fixed owner-hierarchy persistent handle for the
// signing key. Range 0x81010000–0x810FFFFF is user-persistent.
const tpmPersistentHandle = tpm2.TPMHandle(0x81010001)

// openTPM opens the platform's TPM device by delegating to the OS-specific
// tpmOpenDevice function (tpm_open_*.go). Returns nil, nil when no device is
// found; the caller treats that as "TPM unavailable".
func openTPM() (transport.TPMCloser, error) {
	return tpmOpenDevice()
}

// tpmSigner signs with a TPM 2.0 ECDSA P-256 key persisted by the owner.
type tpmSigner struct{}

// tpmECCKeyTemplate returns the ECDSA P-256 signing key template.
func tpmECCKeyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
	}
}

// tpmCreateOrLoadPersistent returns the NamedHandle and public key of the P-256
// ECDSA signing key persisted at tpmPersistentHandle. If the handle is already
// populated, ReadPublic returns the Name; otherwise CreatePrimary + EvictControl
// creates and persists the key first.
//
// The returned NamedHandle carries the TPM Name so callers can pass it directly
// to auth-requiring commands (Sign, etc.) without a separate ReadPublic call.
func tpmCreateOrLoadPersistent(t transport.TPM) (tpm2.NamedHandle, *tpm2.TPMTPublic, error) {
	// Attempt to read an existing key at the well-known persistent handle.
	rpRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpmPersistentHandle,
	}.Execute(t)
	if err == nil {
		pub, err := rpRsp.OutPublic.Contents()
		if err != nil {
			return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: decode persistent key: %w", err)
		}
		return tpm2.NamedHandle{Handle: tpmPersistentHandle, Name: rpRsp.Name}, pub, nil
	}

	// Not present — create a primary under the Owner hierarchy.
	cpRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpmECCKeyTemplate()),
	}.Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: CreatePrimary: %w", err)
	}
	transientHandle := cpRsp.ObjectHandle
	// Always flush the transient context, whether we succeed or fail below.
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: transientHandle}.Execute(t) }()

	// Persist it at the well-known handle. EvictControl requires a NamedHandle
	// (the TPM needs the Name digest to authorise the eviction).
	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: transientHandle,
			Name:   cpRsp.Name,
		},
		PersistentHandle: tpmPersistentHandle,
	}.Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: EvictControl (persist key): %w", err)
	}

	// Now read back to get the persistent handle's canonical Name.
	rpRsp2, err := tpm2.ReadPublic{ObjectHandle: tpmPersistentHandle}.Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: ReadPublic after persist: %w", err)
	}
	pub, err := rpRsp2.OutPublic.Contents()
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: decode persisted key: %w", err)
	}
	return tpm2.NamedHandle{Handle: tpmPersistentHandle, Name: rpRsp2.Name}, pub, nil
}

// tpmPublicToSPKI converts a TPMTPublic ECC key to base64-encoded SPKI DER.
func tpmPublicToSPKI(pub *tpm2.TPMTPublic) (string, error) {
	eccParms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return "", fmt.Errorf("TPM: extract ECC parameters: %w", err)
	}
	eccPoint, err := pub.Unique.ECC()
	if err != nil {
		return "", fmt.Errorf("TPM: extract ECC point: %w", err)
	}
	ecPub, err := tpm2.ECDSAPub(eccParms, eccPoint)
	if err != nil {
		return "", fmt.Errorf("TPM: build ecdsa.PublicKey: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(ecPub)
	if err != nil {
		return "", fmt.Errorf("TPM: marshal SPKI: %w", err)
	}
	return base64.StdEncoding.EncodeToString(spki), nil
}

func (s *tpmSigner) Enrol(_ bool) (string, error) {
	t, err := openTPM()
	if err != nil {
		return "", fmt.Errorf("TPM: open device: %w", err)
	}
	if t == nil {
		return "", fmt.Errorf("TPM: no TPM device found")
	}
	defer t.Close()

	_, pub, err := tpmCreateOrLoadPersistent(t)
	if err != nil {
		return "", err
	}
	return tpmPublicToSPKI(pub)
}

// PublicKeyDER returns the enrolled public key as base64-encoded SPKI DER
// without generating a new key. Returns an error when no TPM device is found
// or when the persistent handle holds no key.
func (s *tpmSigner) PublicKeyDER() (string, error) {
	t, err := openTPM()
	if err != nil {
		return "", fmt.Errorf("TPM: open device: %w", err)
	}
	if t == nil {
		return "", fmt.Errorf("TPM: no TPM device found")
	}
	defer t.Close()

	_, pub, err := tpmCreateOrLoadPersistent(t)
	if err != nil {
		return "", err
	}
	return tpmPublicToSPKI(pub)
}

func (s *tpmSigner) Sign(message string) (string, error) {
	t, err := openTPM()
	if err != nil {
		return "", fmt.Errorf("TPM: open device: %w", err)
	}
	if t == nil {
		return "", fmt.Errorf("TPM: no TPM device found")
	}
	defer t.Close()

	namedHandle, _, err := tpmCreateOrLoadPersistent(t)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256([]byte(message))

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
	}.Execute(t)
	if err != nil {
		return "", fmt.Errorf("TPM: Sign: %w", err)
	}

	ecdsaSig, err := sigRsp.Signature.Signature.ECDSA()
	if err != nil {
		return "", fmt.Errorf("TPM: extract ECDSA signature: %w", err)
	}

	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	sv := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)
	p1363, err := rsToP1363(r, sv)
	if err != nil {
		return "", fmt.Errorf("TPM: %w", err)
	}
	return base64.StdEncoding.EncodeToString(p1363), nil
}
