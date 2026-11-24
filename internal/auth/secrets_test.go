package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewSecretIsUniqueAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		s := NewSecret()
		if !LooksLikeSecret(s) {
			t.Fatalf("NewSecret() = %q fails its own shape check", s)
		}
		if seen[s] {
			t.Fatal("duplicate secret")
		}
		seen[s] = true
	}
}

func TestHashIsSHA256(t *testing.T) {
	h := Hash("abc")
	if len(h) != 32 {
		t.Fatalf("len = %d", len(h))
	}
	if !bytes.Equal(h, Hash("abc")) || bytes.Equal(h, Hash("abd")) {
		t.Fatal("hash is not deterministic or not distinguishing")
	}
}

func TestAPITokenFormat(t *testing.T) {
	tok, prefix := NewAPIToken()
	if !strings.HasPrefix(tok, "nook_pat_") || !LooksLikeAPIToken(tok) {
		t.Fatalf("token %q malformed", tok)
	}
	if !strings.HasPrefix(tok, prefix) || len(prefix) != len("nook_pat_")+4 {
		t.Fatalf("prefix %q does not match token", prefix)
	}
	for _, bad := range []string{"", "nook_pat_", "nook_pat_" + strings.Repeat("A", 52), "ghp_" + NewSecret(), tok + "x", NewSecret()} {
		if LooksLikeAPIToken(bad) {
			t.Errorf("LooksLikeAPIToken(%q) = true", bad)
		}
	}
}

func TestUserCodes(t *testing.T) {
	for range 500 {
		c := NewUserCode()
		if len(c) != userCodeLength {
			t.Fatalf("code %q wrong length", c)
		}
		norm, err := NormalizeUserCode(strings.ToLower(FormatUserCode(c)))
		if err != nil || norm != c {
			t.Fatalf("round trip of %q gave %q, %v", c, norm, err)
		}
		if strings.ContainsAny(c, "AEIOU01") {
			t.Fatalf("code %q contains ambiguous characters", c)
		}
	}
	for _, bad := range []string{"", "BDFG", "BDFG-HJKA", "BDFG-HJKL-M", strings.Repeat("B", 40), "BDFG_HJKL"} {
		if _, err := NormalizeUserCode(bad); err == nil {
			t.Errorf("NormalizeUserCode(%q) accepted", bad)
		}
	}
	if got, _ := NormalizeUserCode(" bdfg hjkl "); got != "BDFGHJKL" {
		t.Errorf("spaces not tolerated: %q", got)
	}
	if FormatUserCode("short") != "short" {
		t.Error("FormatUserCode should leave malformed input alone")
	}
}
