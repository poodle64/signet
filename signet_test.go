package main

import (
	"strings"
	"testing"
)

// TestCanonicalMessage verifies the signed-message construction matches
// the broker's canonical_message(challenge_id, nonce) in attestation.py:
// UTF-8 of "{challenge_id}.{nonce}".
func TestCanonicalMessage(t *testing.T) {
	cases := []struct {
		challengeID string
		nonce       string
		want        string
	}{
		{"abc123", "xyz789", "abc123.xyz789"},
		{"ch-00000000-0000-0000-0000-000000000001", "nonce-val", "ch-00000000-0000-0000-0000-000000000001.nonce-val"},
		{"a", "b", "a.b"},
		{"", "n", ".n"},
	}
	for _, tc := range cases {
		got := canonicalMessage(tc.challengeID, tc.nonce)
		if got != tc.want {
			t.Errorf("canonicalMessage(%q, %q) = %q; want %q", tc.challengeID, tc.nonce, got, tc.want)
		}
	}
}

// TestSanitiseHost verifies the cache filename sanitisation for broker URLs.
func TestSanitiseHost(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"http://localhost:8311", "http_localhost_8311"},
		{"https://portcullis.example.internal", "https_portcullis.example.internal"},
		{"https://portcullis.example.internal/", "https_portcullis.example.internal_"},
		{"https://portcullis.example.internal:8443/api", "https_portcullis.example.internal_8443_api"},
	}
	for _, tc := range cases {
		got := sanitiseHost(tc.input)
		if got != tc.want {
			t.Errorf("sanitiseHost(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

// TestUsageLine verifies the usage string contains all three subcommands.
func TestUsageLine(t *testing.T) {
	line := usageLine()
	for _, sub := range []string{"enrol", "sign", "auth"} {
		if !strings.Contains(line, sub) {
			t.Errorf("usageLine() does not mention %q: %s", sub, line)
		}
	}
}
