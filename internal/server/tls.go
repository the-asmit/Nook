package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/the-asmit/nook/internal/platform/config"
)

// validateTLS enforces "TLS everywhere outside development". The one
// exception: with NOOK_ALLOW_PLAINTEXT_INTERNAL=true, Postgres and Redis
// may be reached without TLS when every host they name is internal (Unix
// socket, loopback, private address or single-label service name), which
// is common for a database on the same host or Docker network. HTTP, the
// public URL and the identity provider always need TLS.
func (c *Config) validateTLS() error {
	var errs []error
	if !c.HTTP.TLSEnabled() {
		errs = append(errs, fmt.Errorf("NOOK_ENV=%s requires NOOK_HTTP_TLS_CERT_PATH and NOOK_HTTP_TLS_KEY_PATH", c.Environment))
	}
	if !c.Identity.UsesTLS() {
		errs = append(errs, fmt.Errorf("NOOK_ENV=%s requires an https:// NOOK_OIDC_ISSUER_URL", c.Environment))
	}
	if !c.Postgres.UsesTLS() && !c.plaintextAllowed(c.Postgres.Hosts()...) {
		errs = append(errs, fmt.Errorf("NOOK_ENV=%s requires NOOK_POSTGRES_URL with sslmode=verify-full (or require/verify-ca)%s",
			c.Environment, c.exceptionHint(c.Postgres.Hosts()...)))
	}
	if !c.Redis.UsesTLS() && !c.plaintextAllowed(c.Redis.Host()) {
		errs = append(errs, fmt.Errorf("NOOK_ENV=%s requires NOOK_REDIS_URL to use the rediss:// scheme%s",
			c.Environment, c.exceptionHint(c.Redis.Host())))
	}
	return errors.Join(errs...)
}

func (c *Config) plaintextAllowed(hosts ...string) bool {
	return c.AllowPlaintextInternal && allInternal(hosts)
}

func (c *Config) exceptionHint(hosts ...string) string {
	if allInternal(hosts) && !c.AllowPlaintextInternal {
		return "; for an internal host you may instead set NOOK_ALLOW_PLAINTEXT_INTERNAL=true"
	}
	return ""
}

func allInternal(hosts []string) bool {
	return len(hosts) > 0 && !slices.ContainsFunc(hosts, func(h string) bool { return !config.IsInternalHost(h) })
}

// PlaintextWarnings lists the connections that run without TLS under the
// NOOK_ALLOW_PLAINTEXT_INTERNAL exception, for a startup warning.
func (c *Config) PlaintextWarnings() []string {
	if !c.Environment.RequiresTLS() || !c.AllowPlaintextInternal {
		return nil
	}
	var out []string
	if !c.Postgres.UsesTLS() {
		out = append(out, "postgres ("+strings.Join(c.Postgres.Hosts(), ", ")+")")
	}
	if !c.Redis.UsesTLS() {
		out = append(out, "redis ("+c.Redis.Host()+")")
	}
	return out
}
