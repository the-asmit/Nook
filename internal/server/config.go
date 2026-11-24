// Package server wires the control plane together: it connects to
// Postgres and Redis, migrates the schema, and serves the HTTP API until
// it is asked to shut down.
package server

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/device"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/httpserver"
	"github.com/the-asmit/nook/internal/platform/logging"
	"github.com/the-asmit/nook/internal/platform/postgres"
	"github.com/the-asmit/nook/internal/platform/redis"
)

// Config is the complete nook-server configuration.
type Config struct {
	// Environment is development, staging or production.
	Environment config.Environment `env:"NOOK_ENV,required,notEmpty"`
	// PublicURL is the address people use in their browsers, e.g.
	// https://nook.example.com. Cookies, CSRF checks, the OIDC redirect URL
	// and the device-flow verification URL all derive from it.
	PublicURL string `env:"NOOK_PUBLIC_URL,required,notEmpty"`
	Log       logging.Config
	HTTP      httpserver.Config
	Postgres  postgres.Config
	Redis     redis.Config
	Auth      auth.Config
	Identity  identity.Config
	Device    device.Config
	// InvitationTTL is how long a workspace invitation stays open.
	InvitationTTL time.Duration `env:"NOOK_INVITATION_TTL" envDefault:"168h"`
	// AllowPlaintextInternal permits non-TLS Postgres and Redis connections
	// outside development when they target internal hosts (see validateTLS).
	AllowPlaintextInternal bool `env:"NOOK_ALLOW_PLAINTEXT_INTERNAL" envDefault:"false"`
	// ReadinessTimeout bounds each dependency probe made by /readyz.
	ReadinessTimeout time.Duration `env:"NOOK_READINESS_TIMEOUT" envDefault:"2s"`
	// StartupTimeout bounds waiting for Postgres, Redis and the identity
	// provider at startup.
	StartupTimeout time.Duration `env:"NOOK_STARTUP_TIMEOUT" envDefault:"30s"`
	// MigrationTimeout bounds waiting for the migration lock plus applying
	// migrations.
	MigrationTimeout time.Duration `env:"NOOK_MIGRATION_TIMEOUT" envDefault:"2m"`
}

// Validate checks every section, then the rules that span sections.
func (c *Config) Validate() error {
	var errs []error
	if err := c.Environment.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("NOOK_ENV: %w", err))
	}
	errs = append(errs,
		c.validatePublicURL(),
		c.Log.Validate(),
		c.HTTP.Validate(),
		c.Postgres.Validate(),
		c.Redis.Validate(),
		c.Auth.Validate(),
		c.Identity.Validate(),
		c.Device.Validate(),
		config.CheckDuration("NOOK_INVITATION_TTL", c.InvitationTTL, time.Hour, 90*24*time.Hour),
		config.CheckDuration("NOOK_READINESS_TIMEOUT", c.ReadinessTimeout, 100*time.Millisecond, 30*time.Second),
		config.CheckDuration("NOOK_STARTUP_TIMEOUT", c.StartupTimeout, time.Second, 10*time.Minute),
		config.CheckDuration("NOOK_MIGRATION_TIMEOUT", c.MigrationTimeout, time.Second, time.Hour),
	)
	if c.ReadinessTimeout >= c.HTTP.RequestTimeout {
		errs = append(errs, fmt.Errorf("NOOK_READINESS_TIMEOUT (%s) must be shorter than NOOK_HTTP_REQUEST_TIMEOUT (%s)",
			c.ReadinessTimeout, c.HTTP.RequestTimeout))
	}
	if c.Environment.RequiresTLS() {
		errs = append(errs, c.validateTLS())
	}
	return errors.Join(errs...)
}

// PublicURLParsed returns the parsed public URL. It is only meaningful on
// a validated Config.
func (c *Config) PublicURLParsed() *url.URL {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return &url.URL{}
	}
	return u
}

func (c *Config) validatePublicURL() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return fmt.Errorf("NOOK_PUBLIC_URL: %w", config.RedactURLError(err))
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("NOOK_PUBLIC_URL: must be http(s)://host[:port] with no path, query or credentials")
	}
	// Plain HTTP means cookies without the Secure flag, which is only
	// acceptable for a developer's own machine.
	if u.Scheme == "http" && (!c.Environment.IsDevelopment() || !config.IsLoopbackHost(u.Hostname())) {
		return errors.New("NOOK_PUBLIC_URL: http:// is only allowed for localhost in development; use https://")
	}
	if c.Identity.RedirectURL != "" {
		r, err := url.Parse(c.Identity.RedirectURL)
		if err == nil && (r.Scheme != u.Scheme || r.Host != u.Host) {
			return errors.New("NOOK_OIDC_REDIRECT_URL: must be on the same origin as NOOK_PUBLIC_URL")
		}
	}
	return nil
}
