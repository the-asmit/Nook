package workspace

import (
	"strings"
	"testing"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/store"
)

func TestValidSlug(t *testing.T) {
	for _, ok := range []string{"a", "team-1", "abc", strings.Repeat("a", 40), "0day"} {
		if !ValidSlug(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a_b", "a.b", strings.Repeat("a", 41), "../x", "a b"} {
		if ValidSlug(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	if n, err := normalizeName("  Team  "); err != nil || n != "Team" {
		t.Fatalf("got %q %v", n, err)
	}
	for _, bad := range []string{"", "  ", strings.Repeat("é", 101), "a\x00b", "tab\tname"} {
		_, err := normalizeName(bad)
		if e, ok := apperr.As(err); !ok || e.Kind != apperr.KindInvalid {
			t.Errorf("%q: err = %v, want invalid", bad, err)
		}
	}
	if _, err := normalizeName(strings.Repeat("é", 100)); err != nil {
		t.Error("100 multi-byte characters must be accepted")
	}
}

func TestNormalizeEmail(t *testing.T) {
	for _, ok := range []string{"a@b.example", " bob@partner.test "} {
		if _, err := normalizeEmail(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "bob", "Bob <bob@x.example>", "a@localhost", strings.Repeat("a", 250) + "@b.example", "a@b@c.example"} {
		if _, err := normalizeEmail(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRoles(t *testing.T) {
	if !atLeast(store.WorkspaceRoleOwner, store.WorkspaceRoleAdmin) ||
		!atLeast(store.WorkspaceRoleAdmin, store.WorkspaceRoleAdmin) ||
		atLeast(store.WorkspaceRoleMember, store.WorkspaceRoleAdmin) ||
		atLeast(store.WorkspaceRole("bogus"), store.WorkspaceRoleMember) {
		t.Fatal("role ordering wrong")
	}
	if _, ok := ParseRole("admin"); !ok {
		t.Error("admin rejected")
	}
	if _, ok := ParseRole("superuser"); ok {
		t.Error("unknown role accepted")
	}
}

func TestRandomSuffix(t *testing.T) {
	s := randomSuffix(4)
	if len(s) != 4 || strings.Trim(s, slugAlphabet) != "" {
		t.Fatalf("randomSuffix = %q", s)
	}
}
