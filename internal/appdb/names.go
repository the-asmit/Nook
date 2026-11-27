package appdb

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"uuid"
)

// Superuser is the role the control plane manages the server with.
const Superuser = "nook_admin"

// namePattern is a database (and role) name Nook creates.
var namePattern = regexp.MustCompile(`^app_[0-9a-f]{32}$`)

// DatabaseName is the database and role name of an app: derived from its
// ID, so it never collides and reveals nothing about the app.
func DatabaseName(appID uuid.UUID) string {
	return "app_" + strings.ReplaceAll(appID.String(), "-", "")
}

// newPassword returns a 256-bit random password (URL-safe, no padding).
func newPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DatabaseURL is the DATABASE_URL an app gets: TLS required (the app does
// not verify the server's certificate, which is from Nook's internal CA).
func DatabaseURL(name, password, address string, port int32) string {
	u := url.URL{
		Scheme: "postgres", User: url.UserPassword(name, password),
		Host: netip.AddrPortFrom(netip.MustParseAddr(address), uint16(port)).String(), //nolint:gosec // G115: a stored port.
		Path: "/" + name, RawQuery: "sslmode=require",
	}
	return u.String()
}

func validHost(h string) bool {
	_, err := netip.ParseAddr(h)
	return err == nil
}

// sqlIdent quotes a name Nook created (validated) as an identifier.
func sqlIdent(name string) (string, error) {
	if !namePattern.MatchString(name) && name != "postgres" && name != "template1" {
		return "", fmt.Errorf("invalid database name %q", name)
	}
	return `"` + name + `"`, nil
}

// sqlLiteral quotes a SCRAM verifier (base64 and "$:") or a number as a
// string literal. DDL cannot take parameters.
func sqlLiteral(s string) (string, error) {
	for _, r := range s {
		if !literalRune(r) {
			return "", errors.New("refusing to quote a value with unexpected characters")
		}
	}
	return "'" + s + "'", nil
}

// literalRune is a character sqlLiteral accepts.
func literalRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("+/=$:-", r)
}
