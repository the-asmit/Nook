// Package auth authenticates requests to the control plane: browser
// sessions, API tokens, CSRF protection and the middleware that turns a
// credential into a Principal.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
)

// secretBytes is the entropy of every bearer secret Nook issues (session
// tokens, API tokens, device codes): 256 bits, far beyond brute force.
const secretBytes = 32

// APITokenPrefix marks Nook personal access tokens. A recognizable prefix
// lets secret scanners (and humans) spot leaked tokens.
const APITokenPrefix = "nook_pat_"

// apiTokenDisplayChars is how many random characters after the prefix are
// kept for display, enough to tell tokens apart, far too few to guess one.
const apiTokenDisplayChars = 4

// encoding is lower-case base32 without padding: URL-, header- and
// shell-safe, and unambiguous when read aloud.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// encodedSecretLen is the length of an encoded 32-byte secret.
var encodedSecretLen = encoding.EncodedLen(secretBytes)

// NewSecret returns a fresh random secret (52 characters).
func NewSecret() string {
	b := make([]byte, secretBytes)
	// crypto/rand.Read never returns an error on supported platforms; it
	// crashes the program instead if the OS entropy source fails.
	_, _ = rand.Read(b)
	return encoding.EncodeToString(b)
}

// Hash returns the SHA-256 digest stored in place of a secret. A plain
// hash (not bcrypt) is right here: the secrets are 256-bit random values,
// so there is nothing for a slow hash to protect against dictionary
// attacks, and lookups must be fast.
func Hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// NewAPIToken returns a new personal access token and its display prefix.
func NewAPIToken() (token, prefix string) {
	token = APITokenPrefix + NewSecret()
	return token, token[:len(APITokenPrefix)+apiTokenDisplayChars]
}

// LooksLikeAPIToken checks a presented token's shape before any database
// lookup, so malformed input is rejected cheaply.
func LooksLikeAPIToken(s string) bool {
	rest, ok := strings.CutPrefix(s, APITokenPrefix)
	return ok && isEncodedSecret(rest)
}

// LooksLikeSecret reports whether s has the shape of a NewSecret value.
func LooksLikeSecret(s string) bool {
	return isEncodedSecret(s)
}

func isEncodedSecret(s string) bool {
	if len(s) != encodedSecretLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// userCodeAlphabet has no vowels (so codes never spell words) and no
// look-alike characters, as RFC 8628 section 6.1 recommends.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// userCodeLength gives 20^8 ≈ 2^34.6 codes. That is enough because a code
// is only valid for minutes, only while pending, and guesses are rate-limited.
const userCodeLength = 8

// NewUserCode returns a random user code in normalized form ("BDFGHJKL").
func NewUserCode() string {
	b := make([]byte, userCodeLength)
	for i := range b {
		// Rejection sampling avoids modulo bias.
		for {
			var r [1]byte
			_, _ = rand.Read(r[:])
			if int(r[0]) < 256-256%len(userCodeAlphabet) {
				b[i] = userCodeAlphabet[int(r[0])%len(userCodeAlphabet)]
				break
			}
		}
	}
	return string(b)
}

// ErrInvalidUserCode is returned for input that cannot be a user code.
var ErrInvalidUserCode = errors.New("not a valid code")

// NormalizeUserCode accepts what a person types ("bdfg-hjkl", " BDFGHJKL ")
// and returns the normalized code.
func NormalizeUserCode(s string) (string, error) {
	if len(s) > 32 {
		return "", ErrInvalidUserCode
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ':
			continue
		case strings.ContainsRune(userCodeAlphabet, r):
			b.WriteRune(r)
		default:
			return "", ErrInvalidUserCode
		}
	}
	if b.Len() != userCodeLength {
		return "", ErrInvalidUserCode
	}
	return b.String(), nil
}

// FormatUserCode renders a normalized code for display ("BDFG-HJKL").
func FormatUserCode(code string) string {
	if len(code) != userCodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}
