package identity

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is what Nook learns about a person from a verified ID token.
type Identity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

// Errors returned by Exchange.
var (
	// ErrNonceMismatch means the ID token was not issued for this sign-in
	// attempt (a replayed or injected token).
	ErrNonceMismatch = errors.New("ID token nonce does not match the sign-in request")
	// ErrNoIDToken means the provider's token response lacked an ID token.
	ErrNoIDToken = errors.New("token response contains no id_token")
)

// ErrProviderUnavailable means OIDC discovery has not succeeded yet.
var ErrProviderUnavailable = errors.New("identity provider is unavailable")

// rediscoverInterval throttles discovery retries while the provider is down.
const rediscoverInterval = 5 * time.Second

// Provider talks to the OpenID Connect provider. Discovery is lazy and
// retried: an identity-provider outage only blocks new sign-ins, never
// server startup or API requests made with existing tokens.
type Provider struct {
	cfg         *Config
	redirectURL string
	client      *http.Client

	mu          sync.Mutex
	discovered  *discovered
	lastAttempt time.Time
}

type discovered struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewProvider returns a provider; call Discover to contact it.
func NewProvider(cfg *Config, redirectURL string) *Provider {
	return &Provider{cfg: cfg, redirectURL: redirectURL, client: &http.Client{Timeout: cfg.HTTPTimeout}}
}

// Discover fetches the provider's metadata if that has not succeeded yet.
// Failed attempts are throttled so an outage is not amplified.
func (p *Provider) Discover(ctx context.Context) error {
	_, err := p.get(ctx)
	return err
}

func (p *Provider) get(ctx context.Context) (*discovered, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.discovered != nil {
		return p.discovered, nil
	}
	if !p.lastAttempt.IsZero() && time.Since(p.lastAttempt) < rediscoverInterval {
		return nil, ErrProviderUnavailable
	}
	p.lastAttempt = time.Now()
	ctx, cancel := context.WithTimeout(ctx, p.cfg.HTTPTimeout)
	defer cancel()
	op, err := oidc.NewProvider(oidc.ClientContext(ctx, p.client), p.cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: discover %s: %w", ErrProviderUnavailable, p.cfg.IssuerURL, err)
	}
	p.discovered = &discovered{
		oauth: oauth2.Config{
			ClientID:     p.cfg.ClientID,
			ClientSecret: p.cfg.ClientSecret.Reveal(),
			Endpoint:     op.Endpoint(),
			RedirectURL:  p.redirectURL,
			Scopes:       p.cfg.Scopes,
		},
		// The verifier checks the signature against the provider's JWKS
		// (refreshed by go-oidc as keys rotate), the issuer, the audience
		// (our client ID) and the expiry.
		verifier: op.Verifier(&oidc.Config{ClientID: p.cfg.ClientID}),
	}
	return p.discovered, nil
}

// AuthCodeURL returns the provider URL that starts an authorization-code
// flow bound to state (CSRF on the callback), nonce (binds the ID token to
// this attempt) and the PKCE verifier (binds the code to this client).
func (p *Provider) AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	d, err := p.get(ctx)
	if err != nil {
		return "", err
	}
	return d.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange redeems an authorization code and returns the verified identity.
func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	d, err := p.get(ctx)
	if err != nil {
		return Identity{}, err
	}
	ctx = oidc.ClientContext(ctx, p.client)
	tok, err := d.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, ErrNoIDToken
	}
	idt, err := d.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify ID token: %w", err)
	}
	return identityFromToken(idt, nonce)
}

// claims are the standard OIDC claims Nook uses. email_verified is decoded
// loosely because some providers send it as the string "true".
type claims struct {
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
	Name          string          `json:"name"`
	Picture       string          `json:"picture"`
}

// identityFromToken checks the nonce and extracts the identity from an ID
// token that has already passed signature, issuer, audience and expiry
// checks.
func identityFromToken(idt *oidc.IDToken, nonce string) (Identity, error) {
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return Identity{}, ErrNonceMismatch
	}
	var c claims
	if err := idt.Claims(&c); err != nil {
		return Identity{}, fmt.Errorf("decode ID token claims: %w", err)
	}
	return Identity{
		Issuer:        idt.Issuer,
		Subject:       idt.Subject,
		Email:         strings.TrimSpace(c.Email),
		EmailVerified: parseVerified(c.EmailVerified),
		Name:          strings.TrimSpace(c.Name),
		Picture:       strings.TrimSpace(c.Picture),
	}, nil
}

func parseVerified(raw json.RawMessage) bool {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	return strings.EqualFold(s, "true")
}
