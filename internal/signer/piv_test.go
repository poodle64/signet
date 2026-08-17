// piv_test.go: hardware-free unit tests for the PIV enrolment management-key
// fallback. The real rotated-card path can only be proven against a physical
// card (that manual run is the verification gate for portcullis#155 step 1);
// these tests exercise the decision logic around it — that a default card still
// works, that a rotated card falls back to the card-held key via the PIN, and
// crucially that a non-terminal stdin fails fast with a distinct error rather
// than blocking on a PIN read that never arrives inside a container.
//
// No PIN value here is a real card PIN; the assertions are on booleans, error
// identity, and which management key was used — never on the PIN.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// fakeKeyGen is a hardware-free stand-in for *piv.YubiKey's enrolment surface.
// The first GenerateKey call models the default-management-key attempt; if
// firstErr is set it is returned, and any later call (the card-held key) reports
// success. It records the management keys it was handed and the PIN Metadata saw
// so a test can assert on the path taken.
type fakeKeyGen struct {
	firstErr   error
	metaResult *piv.Metadata
	metaErr    error
	pub        crypto.PublicKey

	keysUsed   [][]byte
	metaCalled int
	metaPINs   []string
}

func (f *fakeKeyGen) GenerateKey(mk []byte, _ piv.Slot, _ piv.Key) (crypto.PublicKey, error) {
	f.keysUsed = append(f.keysUsed, mk)
	if len(f.keysUsed) == 1 && f.firstErr != nil {
		return nil, f.firstErr
	}
	return f.pub, nil
}

func (f *fakeKeyGen) Metadata(pin string) (*piv.Metadata, error) {
	f.metaCalled++
	f.metaPINs = append(f.metaPINs, pin)
	if f.metaErr != nil {
		return nil, f.metaErr
	}
	return f.metaResult, nil
}

// swErr is a minimal status-word error, matching the interface{ Status() uint16 }
// shape piv's apduErr exposes, so isManagementKeyAuthError's SW-0x6982 branch can
// be exercised without reaching into piv internals.
type swErr struct{ sw uint16 }

func (e swErr) Status() uint16 { return e.sw }
func (e swErr) Error() string  { return "smart card error" }

// withTerminalSeams swaps the package-level TTY/PIN seams for the duration of a
// test and restores them afterwards, tracking whether the PIN prompt was hit.
func withTerminalSeams(t *testing.T, isTTY bool, pin string, pinErr error) (promptCalled *bool) {
	t.Helper()
	called := false
	savedTTY, savedPrompt := pivStdinIsTerminal, pivPromptPIN
	pivStdinIsTerminal = func() bool { return isTTY }
	pivPromptPIN = func() (string, error) {
		called = true
		return pin, pinErr
	}
	t.Cleanup(func() {
		pivStdinIsTerminal = savedTTY
		pivPromptPIN = savedPrompt
	})
	return &called
}

// A card still on factory defaults: the first GenerateKey succeeds, so the PIN
// is never prompted and the management key is never fetched. This is the path
// that must keep working so the change can land before the card is rotated.
func TestGenerateEnrolKey_DefaultCardNeverPrompts(t *testing.T) {
	promptCalled := withTerminalSeams(t, true, "unused", nil)
	s := &pivSigner{slot: piv.SlotSignature, label: "9c"}
	yk := &fakeKeyGen{pub: dummyPub()}

	if _, err := s.generateEnrolKey(yk); err != nil {
		t.Fatalf("default-card enrol: %v", err)
	}
	if *promptCalled {
		t.Fatal("PIN prompt was called for a default card; the default path must not touch the PIN")
	}
	if yk.metaCalled != 0 {
		t.Fatalf("Metadata called %d times for a default card; want 0", yk.metaCalled)
	}
	if len(yk.keysUsed) != 1 || !bytesEqual(yk.keysUsed[0], piv.DefaultManagementKey[:]) {
		t.Fatalf("default card must be written with the default management key, keysUsed=%d", len(yk.keysUsed))
	}
}

// A rotated card with stdin NOT a terminal: enrolment must refuse fast with the
// distinct errEnrolNeedsTerminal, never call the PIN prompt, and never call
// Metadata. This is the container case — a hang here is the worst failure mode.
func TestGenerateEnrolKey_NotATerminalRefusesFast(t *testing.T) {
	promptCalled := withTerminalSeams(t, false, "unused", nil)
	s := &pivSigner{slot: piv.SlotSignature, label: "9c"}
	yk := &fakeKeyGen{firstErr: piv.AuthErr{Retries: 2}}

	_, err := s.generateEnrolKey(yk)
	if !errors.Is(err, errEnrolNeedsTerminal) {
		t.Fatalf("want errEnrolNeedsTerminal for non-terminal stdin, got %v", err)
	}
	if *promptCalled {
		t.Fatal("PIN prompt was called with a non-terminal stdin; it must refuse before prompting")
	}
	if yk.metaCalled != 0 {
		t.Fatalf("Metadata called %d times on refusal; want 0 (must not touch the card)", yk.metaCalled)
	}
}

// A rotated, PIN-protected card at an interactive terminal: the default key is
// refused, the PIN is prompted, Metadata returns the card-held key, and the key
// is written with it. Covers the fallback wiring end-to-end minus real hardware.
func TestGenerateEnrolKey_RotatedCardFallsBackToCardHeldKey(t *testing.T) {
	promptCalled := withTerminalSeams(t, true, "123456", nil)
	cardKey := []byte("card-held-management-key-24bytes")
	s := &pivSigner{slot: piv.SlotSignature, label: "9c"}
	yk := &fakeKeyGen{
		firstErr:   swErr{sw: 0x6982}, // security status not satisfied — wrong mgmt key
		metaResult: &piv.Metadata{ManagementKey: &cardKey},
		pub:        dummyPub(),
	}

	if _, err := s.generateEnrolKey(yk); err != nil {
		t.Fatalf("rotated-card fallback: %v", err)
	}
	if !*promptCalled {
		t.Fatal("PIN prompt was not called for a rotated card")
	}
	if yk.metaCalled != 1 || len(yk.metaPINs) != 1 || yk.metaPINs[0] != "123456" {
		t.Fatalf("Metadata not called once with the prompted PIN: calls=%d pins=%v", yk.metaCalled, yk.metaPINs)
	}
	if len(yk.keysUsed) != 2 || !bytesEqual(yk.keysUsed[1], cardKey) {
		t.Fatalf("second GenerateKey must use the card-held key, keysUsed=%d", len(yk.keysUsed))
	}
}

// A rotated card that holds no PIN-protected management key (neither default nor
// on-card protected): enrolment must refuse with a message naming the supported
// shapes, and must not attempt a second write.
func TestGenerateEnrolKey_NoCardHeldKeyRefuses(t *testing.T) {
	withTerminalSeams(t, true, "123456", nil)
	s := &pivSigner{slot: piv.SlotSignature, label: "9c"}
	yk := &fakeKeyGen{
		firstErr:   piv.AuthErr{Retries: 3},
		metaResult: &piv.Metadata{}, // nil ManagementKey
	}

	_, err := s.generateEnrolKey(yk)
	if err == nil {
		t.Fatal("want an error when the card holds no PIN-protected management key")
	}
	if !strings.Contains(err.Error(), "PIN-protected") {
		t.Fatalf("error should name the supported shape, got %v", err)
	}
	if len(yk.keysUsed) != 1 {
		t.Fatalf("must not attempt a second write with no card-held key, keysUsed=%d", len(yk.keysUsed))
	}
}

// A GenerateKey failure that is NOT a management-key auth error (e.g. the card
// vanished mid-call) must be surfaced as-is — never mistaken for a rotated card,
// never prompting for a PIN.
func TestGenerateEnrolKey_NonAuthErrorSurfacedNotPrompted(t *testing.T) {
	promptCalled := withTerminalSeams(t, true, "unused", nil)
	s := &pivSigner{slot: piv.SlotSignature, label: "9c"}
	yk := &fakeKeyGen{firstErr: errors.New("card removed")}

	_, err := s.generateEnrolKey(yk)
	if err == nil || !strings.Contains(err.Error(), "GenerateKey (slot 9c)") {
		t.Fatalf("non-auth error should surface directly, got %v", err)
	}
	if *promptCalled {
		t.Fatal("a non-auth failure must not trigger the PIN prompt")
	}
	if yk.metaCalled != 0 {
		t.Fatalf("Metadata called %d times on a non-auth failure; want 0", yk.metaCalled)
	}
}

func TestIsManagementKeyAuthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"piv.AuthErr", piv.AuthErr{Retries: 1}, true},
		{"wrapped piv.AuthErr", fmt.Errorf("authenticating: %w", piv.AuthErr{Retries: 1}), true},
		{"sw 0x6982", swErr{sw: 0x6982}, true},
		{"wrapped sw 0x6982", fmt.Errorf("command failed: %w", swErr{sw: 0x6982}), true},
		{"sw 0x9000 (ok)", swErr{sw: 0x9000}, false},
		{"plain error", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isManagementKeyAuthError(c.err); got != c.want {
				t.Fatalf("isManagementKeyAuthError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// dummyPub is a stand-in public key for the fake's successful GenerateKey.
// generateEnrolKey returns it unmodified (the *ecdsa type assertion lives in
// Enrol), so these tests only need a non-nil crypto.PublicKey.
func dummyPub() crypto.PublicKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &k.PublicKey
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
