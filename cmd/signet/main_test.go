package main

import (
	"strings"
	"testing"
)

// TestHelpText verifies the help block mentions all subcommands.
func TestHelpText(t *testing.T) {
	text := helpText()
	for _, sub := range []string{"enrol", "sign", "auth", "verify", "headers", "agent", "version", "doctor"} {
		if !strings.Contains(text, sub) {
			t.Errorf("helpText() does not mention %q", sub)
		}
	}
}

// TestBindList verifies the repeatable --bind flag accumulator.
func TestBindList(t *testing.T) {
	var b bindList
	if err := b.Set("/run/signet/a.sock=9c"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := b.Set("/run/signet/b.sock=9d"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(b) != 2 {
		t.Fatalf("len = %d, want 2", len(b))
	}
	if got := b.String(); got != "/run/signet/a.sock=9c,/run/signet/b.sock=9d" {
		t.Errorf("String() = %q", got)
	}
}

// TestRunHeadersFlagValidation pins the cmd-layer gate for `headers`: the
// required/enum/non-empty checks must all fail fast (exit 1) before any
// signer or network work happens.
func TestRunHeadersFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing broker", []string{"--credential", "example-api"}},
		{"missing credential", []string{"--broker", "https://broker.internal"}},
		{"empty header", []string{"--broker", "https://broker.internal", "--credential", "example-api", "--header", " "}},
		{"bogus format", []string{"--broker", "https://broker.internal", "--credential", "example-api", "--format", "bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runHeaders(tc.args); got != 1 {
				t.Errorf("runHeaders(%v) = %d, want 1", tc.args, got)
			}
		})
	}
}
