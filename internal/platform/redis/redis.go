// Package redis builds the go-redis client Nook uses for its build queue,
// route change notifications and rate limiting.
package redis

import (
	"errors"
	"fmt"
	"net"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config holds client settings.
type Config struct {
	// URL is redis://[:password@]host:port/db, or rediss:// for TLS.
	URL config.Secret `env:"NOOK_REDIS_URL,required,notEmpty"`
	// DialTimeout bounds establishing a connection.
	DialTimeout time.Duration `env:"NOOK_REDIS_DIAL_TIMEOUT" envDefault:"5s"`
	// ReadTimeout bounds waiting for a reply.
	ReadTimeout time.Duration `env:"NOOK_REDIS_READ_TIMEOUT" envDefault:"3s"`
	// WriteTimeout bounds sending a command.
	WriteTimeout time.Duration `env:"NOOK_REDIS_WRITE_TIMEOUT" envDefault:"3s"`
	// PoolSize caps open connections.
	PoolSize int `env:"NOOK_REDIS_POOL_SIZE" envDefault:"10"`
}

// Validate checks limits and that the URL parses (without connecting).
func (c *Config) Validate() error {
	var errs []error
	if _, err := goredis.ParseURL(c.URL.Reveal()); err != nil {
		errs = append(errs, fmt.Errorf("NOOK_REDIS_URL: %w", config.RedactURLError(err)))
	}
	errs = append(errs,
		config.CheckDuration("NOOK_REDIS_DIAL_TIMEOUT", c.DialTimeout, 100*time.Millisecond, time.Minute),
		config.CheckDuration("NOOK_REDIS_READ_TIMEOUT", c.ReadTimeout, 100*time.Millisecond, time.Minute),
		config.CheckDuration("NOOK_REDIS_WRITE_TIMEOUT", c.WriteTimeout, 100*time.Millisecond, time.Minute),
		config.CheckRange("NOOK_REDIS_POOL_SIZE", c.PoolSize, 1, 1000),
	)
	return errors.Join(errs...)
}

// UsesTLS reports whether the URL selects TLS (the rediss:// scheme).
func (c *Config) UsesTLS() bool {
	opts, err := goredis.ParseURL(c.URL.Reveal())
	return err == nil && opts.TLSConfig != nil
}

// NewClient creates a client. Like database/sql, go-redis connects lazily,
// so reachability is checked separately with Ping.
func NewClient(cfg *Config) (*goredis.Client, error) {
	opts, err := goredis.ParseURL(cfg.URL.Reveal())
	if err != nil {
		return nil, fmt.Errorf("parse NOOK_REDIS_URL: %w", config.RedactURLError(err))
	}
	opts.DialTimeout = cfg.DialTimeout
	opts.ReadTimeout = cfg.ReadTimeout
	opts.WriteTimeout = cfg.WriteTimeout
	opts.PoolSize = cfg.PoolSize
	// Without this, go-redis ignores context deadlines and only applies the
	// fixed read/write timeouts, which breaks per-request time budgets.
	opts.ContextTimeoutEnabled = true
	return goredis.NewClient(opts), nil
}

// Host returns the host the URL connects to, or the socket path for
// unix:// URLs.
func (c *Config) Host() string {
	opts, err := goredis.ParseURL(c.URL.Reveal())
	if err != nil {
		return ""
	}
	if opts.Network == "unix" {
		return opts.Addr
	}
	host, _, err := net.SplitHostPort(opts.Addr)
	if err != nil {
		return opts.Addr
	}
	return host
}
