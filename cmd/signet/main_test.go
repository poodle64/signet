package main

import (
	"strings"
	"testing"
)

// TestHelpText verifies the help block mentions all subcommands.
func TestHelpText(t *testing.T) {
	text := helpText()
	for _, sub := range []string{"enrol", "sign", "auth", "verify", "headers", "vend-to-file", "agent", "version", "doctor"} {
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

// TestRunVendToFileFlagValidation pins the cmd-layer gate for `vend-to-file`:
// the required/octal checks must all fail fast (exit 1) before any signer or
// network work happens.
func TestRunVendToFileFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing broker", []string{"my-cred", "/tmp/dest"}},
		{"missing name and dest", []string{"--broker", "https://broker.internal"}},
		{"missing dest", []string{"--broker", "https://broker.internal", "my-cred"}},
		{"bogus mode", []string{"--broker", "https://broker.internal", "--mode", "not-octal", "my-cred", "/tmp/dest"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runVendToFile(tc.args); got != 1 {
				t.Errorf("runVendToFile(%v) = %d, want 1", tc.args, got)
			}
		})
	}
}

// TestParseFileMode verifies octal file-mode flag parsing, with and without
// a leading zero, and rejects non-octal input.
func TestParseFileMode(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"0600", 0o600},
		{"600", 0o600},
		{"0640", 0o640},
		{"0400", 0o400},
		{"07777", 0o7777}, // the top of the 12-bit POSIX permission/sticky/setuid/setgid range
	}
	for _, tc := range cases {
		got, err := parseFileMode(tc.input)
		if err != nil {
			t.Fatalf("parseFileMode(%q): %v", tc.input, err)
		}
		if int(got) != tc.want {
			t.Errorf("parseFileMode(%q) = %o, want %o", tc.input, got, tc.want)
		}
	}

	if _, err := parseFileMode("not-octal"); err == nil {
		t.Error("expected error for non-octal mode, got nil")
	}
	if _, err := parseFileMode("999"); err == nil {
		t.Error("expected error for out-of-range octal digits, got nil")
	}

	// A mode past the 12-bit POSIX range must be rejected with a clear
	// "out of range" error, not silently truncated by os.Chmod into a
	// confusing "----------" dest (the footgun this bound closes).
	rangeCases := []string{"010000", "20000000000"}
	for _, in := range rangeCases {
		_, err := parseFileMode(in)
		if err == nil {
			t.Errorf("parseFileMode(%q): expected an out-of-range error, got nil", in)
			continue
		}
		if !strings.Contains(err.Error(), "out of range") {
			t.Errorf("parseFileMode(%q) error = %q, want it to mention \"out of range\"", in, err.Error())
		}
	}
}
