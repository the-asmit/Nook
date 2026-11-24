package identity

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/the-asmit/nook/internal/platform/config"
)

func validConfig() Config {
	return Config{
		IssuerURL: "https://accounts.google.com", ClientID: "id", ClientSecret: config.NewSecret("s"),
		Scopes: []string{"openid", "email", "profile"}, ProviderName: "Google", HTTPTimeout: 10 * time.Second,
		AllowedEmailDomains: []string{"example.com"},
	}
}

func TestConfigValidate(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){
		"issuer not url":      func(c *Config) { c.IssuerURL = "accounts.google.com" },
		"issuer credentials":  func(c *Config) { c.IssuerURL = "https://u:p@idp.example.com" },
		"missing openid":      func(c *Config) { c.Scopes = []string{"email"} },
		"upper-case domain":   func(c *Config) { c.AllowedEmailDomains = []string{"Example.com"} },
		"ip as domain":        func(c *Config) { c.AllowedEmailDomains = []string{"10.0.0.1"} },
		"bad bootstrap":       func(c *Config) { c.BootstrapAdminEmails = []string{"not-an-email"} },
		"nobody admitted":     func(c *Config) { c.AllowedEmailDomains = nil },
		"redirect with query": func(c *Config) { c.RedirectURL = "https://nook.example.com/auth/callback?x=1" },
	}
	for name, mutate := range cases {
		c := validConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResolveRedirectURLAndTLS(t *testing.T) {
	c := validConfig()
	pub := &url.URL{Scheme: "https", Host: "nook.example.com"}
	if got := c.ResolveRedirectURL(pub); got != "https://nook.example.com/auth/callback" {
		t.Errorf("default redirect = %q", got)
	}
	c.RedirectURL = "https://nook.example.com/custom"
	if got := c.ResolveRedirectURL(pub); got != c.RedirectURL {
		t.Errorf("explicit redirect = %q", got)
	}
	if !c.UsesTLS() {
		t.Error("https issuer should use TLS")
	}
	c.IssuerURL = "http://localhost:5556/dex"
	if c.UsesTLS() {
		t.Error("http issuer reported as TLS")
	}
}

func TestPolicy(t *testing.T) {
	p := NewPolicy(&Config{AllowedEmailDomains: []string{"example.com"}, BootstrapAdminEmails: []string{"Boss@Other.org"}})
	if !p.DomainAllowed("a@EXAMPLE.com") || p.DomainAllowed("a@sub.example.com") || p.DomainAllowed("a@example.com.evil") {
		t.Error("domain matching must be exact and case-insensitive")
	}
	if !p.IsBootstrapAdmin("boss@other.org") || p.IsBootstrapAdmin("boss@example.com") {
		t.Error("bootstrap matching wrong")
	}
	if p.DomainAllowed("no-at-sign") {
		t.Error("malformed email allowed")
	}
}

func TestParseVerified(t *testing.T) {
	cases := map[string]bool{`true`: true, `"true"`: true, `"TRUE"`: true, `false`: false, `"false"`: false, `null`: false, ``: false, `1`: false}
	for raw, want := range cases {
		if got := parseVerified(json.RawMessage(raw)); got != want {
			t.Errorf("parseVerified(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestNonceMismatchIsRejected(t *testing.T) {
	for _, tc := range []struct{ token, expected string }{
		{"nonce-from-another-attempt", "our-nonce"},
		{"", "our-nonce"},
		{"x", ""},
	} {
		_, err := identityFromToken(&oidc.IDToken{Nonce: tc.token}, tc.expected)
		if !errors.Is(err, ErrNonceMismatch) {
			t.Errorf("token nonce %q vs %q: err = %v, want ErrNonceMismatch", tc.token, tc.expected, err)
		}
	}
}

func TestTruncateRunesAndDomain(t *testing.T) {
	if truncateRunes("héllo", 2) != "hé" || truncateRunes("ab", 5) != "ab" {
		t.Error("truncateRunes wrong")
	}
	if emailDomain("A@Example.COM") != "example.com" || emailDomain("none") != "" {
		t.Error("emailDomain wrong")
	}
	if !strings.HasPrefix(ErrNotInvited.Error(), "this email") {
		t.Error("error text changed")
	}
}
