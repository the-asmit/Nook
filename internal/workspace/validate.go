package workspace

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/store"
)

// slugPattern matches the workspaces_slug_format constraint: lower-case
// letters, digits and inner hyphens, 1 to 40 characters. Slugs appear in
// URLs and must stay stable, so they cannot be changed after creation.
var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// maxNameLength matches the workspaces_name_length constraint.
const maxNameLength = 100

// ValidSlug reports whether s is an acceptable workspace slug.
func ValidSlug(s string) bool {
	return slugPattern.MatchString(s)
}

// normalizeName trims a display name and rejects empty, overlong or
// control-character-containing names.
func normalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxNameLength {
		return "", apperr.Invalid("invalid_name", "name must be 1 to %d characters", maxNameLength)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", apperr.Invalid("invalid_name", "name must not contain control characters")
		}
	}
	return name, nil
}

// normalizeEmail accepts a bare address ("a@b.example") and rejects display
// names, overlong input and other RFC 5322 forms people do not type.
func normalizeEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 254 {
		return "", apperr.Invalid("invalid_email", "email address is too long")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Name != "" || addr.Address != s || !strings.Contains(s[strings.LastIndexByte(s, '@')+1:], ".") {
		return "", apperr.Invalid("invalid_email", "%q is not a valid email address", s)
	}
	return s, nil
}

// slugAlphabet is used for random slug suffixes.
const slugAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// personalSlug finds an unused slug derived from an email's local part
// ("jane.doe@x" -> "jane-doe", or "jane-doe-k3x9" if taken). Checking
// first instead of catching a unique violation keeps the surrounding
// transaction usable.
func personalSlug(ctx context.Context, q *store.Queries, email string) (string, error) {
	local, _, _ := strings.Cut(strings.ToLower(email), "@")
	var b strings.Builder
	lastHyphen := true
	for _, r := range local {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastHyphen = false
		} else if !lastHyphen {
			b.WriteByte('-')
			lastHyphen = true
		}
	}
	base := strings.Trim(b.String(), "-")
	if len(base) > 30 {
		base = strings.TrimRight(base[:30], "-")
	}
	if base == "" {
		base = "user"
	}

	candidate := base
	for range 10 {
		taken, err := q.WorkspaceSlugExists(ctx, candidate)
		if err != nil {
			return "", fmt.Errorf("check slug: %w", err)
		}
		if !taken {
			return candidate, nil
		}
		candidate = base + "-" + randomSuffix(4)
	}
	return "", fmt.Errorf("no free workspace slug for %q after 10 attempts", base)
}

func randomSuffix(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		// 256 is not a multiple of 36, but a slight bias in a uniqueness
		// suffix is harmless.
		b[i] = slugAlphabet[int(b[i])%len(slugAlphabet)]
	}
	return string(b)
}
