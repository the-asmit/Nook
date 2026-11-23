// Package postgres builds the pgx connection pool Nook uses for its own
// state and applies schema migrations safely when several instances start
// at once.
package postgres

import (
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config holds connection pool settings.
type Config struct {
	// URL is a libpq connection string, e.g. postgres://user:pass@host:5432/db?sslmode=verify-full.
	URL config.Secret `env:"NOOK_POSTGRES_URL,required,notEmpty"`
	// MaxConns caps open connections. Postgres pays a process per
	// connection, so this is deliberately small.
	MaxConns int32 `env:"NOOK_POSTGRES_MAX_CONNS" envDefault:"10"`
	// MinConns keeps warm connections so the first requests after idle
	// periods do not pay the connection handshake.
	MinConns int32 `env:"NOOK_POSTGRES_MIN_CONNS" envDefault:"1"`
	// MaxConnLifetime recycles connections so server-side memory bloat and
	// DNS/failover changes are picked up.
	MaxConnLifetime time.Duration `env:"NOOK_POSTGRES_MAX_CONN_LIFETIME" envDefault:"30m"`
	// MaxConnIdleTime closes connections that have been idle this long.
	MaxConnIdleTime time.Duration `env:"NOOK_POSTGRES_MAX_CONN_IDLE_TIME" envDefault:"5m"`
	// HealthCheckPeriod is how often idle connections are checked.
	HealthCheckPeriod time.Duration `env:"NOOK_POSTGRES_HEALTH_CHECK_PERIOD" envDefault:"30s"`
	// ConnectTimeout bounds establishing a single connection.
	ConnectTimeout time.Duration `env:"NOOK_POSTGRES_CONNECT_TIMEOUT" envDefault:"5s"`
}

// Validate checks limits and that the URL parses (without connecting).
func (c *Config) Validate() error {
	var errs []error
	if _, err := pgxpool.ParseConfig(c.URL.Reveal()); err != nil {
		// pgx redacts the password in its parse errors.
		errs = append(errs, fmt.Errorf("NOOK_POSTGRES_URL: %w", err))
	}
	errs = append(errs,
		config.CheckRange[int32]("NOOK_POSTGRES_MAX_CONNS", c.MaxConns, 1, 1000),
		config.CheckRange("NOOK_POSTGRES_MIN_CONNS", c.MinConns, 0, c.MaxConns),
		config.CheckDuration("NOOK_POSTGRES_MAX_CONN_LIFETIME", c.MaxConnLifetime, time.Minute, 24*time.Hour),
		config.CheckDuration("NOOK_POSTGRES_MAX_CONN_IDLE_TIME", c.MaxConnIdleTime, time.Second, 24*time.Hour),
		config.CheckDuration("NOOK_POSTGRES_HEALTH_CHECK_PERIOD", c.HealthCheckPeriod, time.Second, time.Hour),
		config.CheckDuration("NOOK_POSTGRES_CONNECT_TIMEOUT", c.ConnectTimeout, 100*time.Millisecond, time.Minute),
	)
	return errors.Join(errs...)
}

// UsesTLS reports whether every connection attempt uses TLS. sslmode
// "prefer" (the libpq default) and "allow" fall back to plaintext, so they
// do not count.
func (c *Config) UsesTLS() bool {
	pc, err := pgxpool.ParseConfig(c.URL.Reveal())
	if err != nil {
		return false
	}
	if pc.ConnConfig.TLSConfig == nil {
		return false
	}
	for _, fb := range pc.ConnConfig.Fallbacks {
		if fb.TLSConfig == nil {
			return false
		}
	}
	return true
}

// poolConfig turns c into a pgx pool configuration. Explicit settings
// override any pool_* parameters embedded in the URL.
func (c *Config) poolConfig(applicationName string) (*pgxpool.Config, error) {
	pc, err := pgxpool.ParseConfig(c.URL.Reveal())
	if err != nil {
		return nil, fmt.Errorf("parse NOOK_POSTGRES_URL: %w", err)
	}
	pc.MaxConns = c.MaxConns
	pc.MinConns = c.MinConns
	pc.MaxConnLifetime = c.MaxConnLifetime
	// Jitter spreads reconnects so all connections do not expire together.
	pc.MaxConnLifetimeJitter = c.MaxConnLifetime / 10
	pc.MaxConnIdleTime = c.MaxConnIdleTime
	pc.HealthCheckPeriod = c.HealthCheckPeriod
	pc.ConnConfig.ConnectTimeout = c.ConnectTimeout
	if _, set := pc.ConnConfig.RuntimeParams["application_name"]; !set {
		// Shows up in pg_stat_activity, which makes debugging much easier.
		pc.ConnConfig.RuntimeParams["application_name"] = applicationName
	}
	return pc, nil
}
