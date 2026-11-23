// Package server wires the control plane together: it connects to
// Postgres and Redis, migrates the schema, and serves the HTTP API until
// it is asked to shut down.
package server

import (
	"errors"
	"fmt"
	"time"

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
	Log         logging.Config
	HTTP        httpserver.Config
	Postgres    postgres.Config
	Redis       redis.Config
	// ReadinessTimeout bounds each dependency probe made by /readyz.
	ReadinessTimeout time.Duration `env:"NOOK_READINESS_TIMEOUT" envDefault:"2s"`
	// StartupTimeout bounds waiting for Postgres and Redis at startup.
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
		c.Log.Validate(),
		c.HTTP.Validate(),
		c.Postgres.Validate(),
		c.Redis.Validate(),
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

// validateTLS enforces "TLS everywhere outside development": in staging
// and production no connection may fall back to plaintext.
func (c *Config) validateTLS() error {
	var errs []error
	if !c.HTTP.TLSEnabled() {
		errs = append(errs, fmt.Errorf("NOOK_ENV=%s requires NOOK_HTTP_TLS_CERT_PATH and NOOK_HTTP_TLS_KEY_PATH", c.Environment))
	}
	if !c.Postgres.UsesTLS() {
		errs = append(errs, fmt.Errorf("NOOK_ENV=%s requires NOOK_POSTGRES_URL with sslmode=verify-full (or require/verify-ca)", c.Environment))
	}
	if !c.Redis.UsesTLS() {
		errs = append(errs, fmt.Errorf("NOOK_ENV=%s requires NOOK_REDIS_URL to use the rediss:// scheme", c.Environment))
	}
	return errors.Join(errs...)
}
