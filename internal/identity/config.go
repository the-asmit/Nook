// Package identity signs people in through an OpenID Connect provider and
// decides who may have an account: the allowed-domain / invitation policy,
// first-login provisioning and invitation acceptance.
package identity

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// CallbackPath is where the identity provider sends the browser back.
const CallbackPath = "/auth/callback"

// Config configures the OIDC provider and the sign-in policy.
type Config struct {
	// IssuerURL is the provider's issuer, e.g. https://accounts.google.com.
	IssuerURL string `env:"NOOK_OIDC_ISSUER_URL,required,notEmpty"`
	// ClientID and ClientSecret identify Nook to the provider.
	ClientID     string        `env:"NOOK_OIDC_CLIENT_ID,required,notEmpty"`
	ClientSecret config.Secret `env:"NOOK_OIDC_CLIENT_SECRET,required,notEmpty"`
	// RedirectURL must be registered with the provider. Default:
	// NOOK_PUBLIC_URL + /auth/callback.
	RedirectURL string `env:"NOOK_OIDC_REDIRECT_URL"`
	// Scopes requested; openid and email are mandatory.
	Scopes []string `env:"NOOK_OIDC_SCOPES" envSeparator:"," envDefault:"openid,email,profile"`
	// ProviderName is shown on the sign-in button ("Sign in with Google").
	ProviderName string `env:"NOOK_OIDC_PROVIDER_NAME" envDefault:"single sign-on"`
	// HTTPTimeout bounds every request to the provider.
	HTTPTimeout time.Duration `env:"NOOK_OIDC_HTTP_TIMEOUT" envDefault:"10s"`
	// AllowedEmailDomains may create accounts without an invitation.
	AllowedEmailDomains []string `env:"NOOK_ALLOWED_EMAIL_DOMAINS" envSeparator:","`
	// BootstrapAdminEmails may always sign in and become instance admins.
	BootstrapAdminEmails []string `env:"NOOK_BOOTSTRAP_ADMIN_EMAILS" envSeparator:","`
}

// Validate checks the provider settings and the policy lists.
func (c *Config) Validate() error {
	var errs []error
	if err := checkHTTPURL(c.IssuerURL); err != nil {
		errs = append(errs, fmt.Errorf("NOOK_OIDC_ISSUER_URL: %w", err))
	}
	if c.RedirectURL != "" {
		if err := checkHTTPURL(c.RedirectURL); err != nil {
			errs = append(errs, fmt.Errorf("NOOK_OIDC_REDIRECT_URL: %w", err))
		}
	}
	if len(c.ClientID) > 512 {
		errs = append(errs, errors.New("NOOK_OIDC_CLIENT_ID: longer than 512 characters"))
	}
	if !slices.Contains(c.Scopes, "openid") || !slices.Contains(c.Scopes, "email") {
		errs = append(errs, errors.New(`NOOK_OIDC_SCOPES: must include "openid" and "email"`))
	}
	if n := len(c.ProviderName); n == 0 || n > 60 {
		errs = append(errs, errors.New("NOOK_OIDC_PROVIDER_NAME: must be 1 to 60 characters"))
	}
	errs = append(errs, config.CheckDuration("NOOK_OIDC_HTTP_TIMEOUT", c.HTTPTimeout, time.Second, time.Minute))
	for _, d := range c.AllowedEmailDomains {
		if !validDomain(d) {
			errs = append(errs, fmt.Errorf("NOOK_ALLOWED_EMAIL_DOMAINS: %q is not a lower-case domain name", d))
		}
	}
	for _, e := range c.BootstrapAdminEmails {
		if _, domain, ok := strings.Cut(e, "@"); !ok || !validDomain(strings.ToLower(domain)) {
			errs = append(errs, fmt.Errorf("NOOK_BOOTSTRAP_ADMIN_EMAILS: %q is not an email address", e))
		}
	}
	if len(c.AllowedEmailDomains) == 0 && len(c.BootstrapAdminEmails) == 0 {
		// Nobody could ever sign in, and so nobody could invite anyone.
		errs = append(errs, errors.New("set NOOK_ALLOWED_EMAIL_DOMAINS or NOOK_BOOTSTRAP_ADMIN_EMAILS (or both)"))
	}
	return errors.Join(errs...)
}

// ResolveRedirectURL returns the configured redirect URL, or the default
// derived from the public URL.
func (c *Config) ResolveRedirectURL(publicURL *url.URL) string {
	if c.RedirectURL != "" {
		return c.RedirectURL
	}
	return publicURL.Scheme + "://" + publicURL.Host + CallbackPath
}

// UsesTLS reports whether the issuer is reached over HTTPS.
func (c *Config) UsesTLS() bool {
	u, err := url.Parse(c.IssuerURL)
	return err == nil && u.Scheme == "https"
}

func checkHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return config.RedactURLError(err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an http(s) URL with a host and no credentials, query or fragment")
	}
	return nil
}

func validDomain(d string) bool {
	if d == "" || len(d) > 253 || d != strings.ToLower(d) || net.ParseIP(d) != nil || !strings.Contains(d, ".") {
		return false
	}
	for label := range strings.SplitSeq(d, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
