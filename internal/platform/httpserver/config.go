// Package httpserver runs an HTTP server with production timeouts and
// graceful shutdown, and provides the middleware every Nook HTTP API uses:
// request IDs, panic recovery, access logs, metrics, per-request timeouts,
// body size limits and security headers.
package httpserver

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config holds listener, timeout and limit settings.
type Config struct {
	// Addr is the listen address, e.g. ":8080" or "127.0.0.1:8080".
	Addr string `env:"NOOK_HTTP_ADDR" envDefault:":8080"`
	// ReadHeaderTimeout bounds reading request headers; it is the main
	// defense against slow-loris clients holding connections open.
	ReadHeaderTimeout time.Duration `env:"NOOK_HTTP_READ_HEADER_TIMEOUT" envDefault:"5s"`
	// ReadTimeout bounds reading the whole request, body included.
	ReadTimeout time.Duration `env:"NOOK_HTTP_READ_TIMEOUT" envDefault:"15s"`
	// WriteTimeout bounds writing the response; the connection is cut after it.
	WriteTimeout time.Duration `env:"NOOK_HTTP_WRITE_TIMEOUT" envDefault:"30s"`
	// IdleTimeout closes keep-alive connections idle this long.
	IdleTimeout time.Duration `env:"NOOK_HTTP_IDLE_TIMEOUT" envDefault:"60s"`
	// RequestTimeout is the deadline placed on each request's context. It
	// must be shorter than WriteTimeout so handlers can still answer with
	// an error before the server drops the connection.
	RequestTimeout time.Duration `env:"NOOK_HTTP_REQUEST_TIMEOUT" envDefault:"20s"`
	// ShutdownTimeout is how long in-flight requests get to finish after
	// SIGTERM before connections are closed forcibly.
	ShutdownTimeout time.Duration `env:"NOOK_HTTP_SHUTDOWN_TIMEOUT" envDefault:"20s"`
	// MaxBodyBytes caps request body size.
	MaxBodyBytes int64 `env:"NOOK_HTTP_MAX_BODY_BYTES" envDefault:"1048576"`
	// TrustedProxies lists the IPs or CIDRs allowed to set X-Forwarded-For.
	// Empty means the client IP is always the TCP peer address, which
	// prevents clients from spoofing their address in logs.
	TrustedProxies []string `env:"NOOK_HTTP_TRUSTED_PROXIES" envSeparator:","`
	// TLSCertPath and TLSKeyPath enable HTTPS when both are set.
	TLSCertPath string `env:"NOOK_HTTP_TLS_CERT_PATH"`
	// TLSKeyPath is the PEM private key matching TLSCertPath.
	TLSKeyPath string `env:"NOOK_HTTP_TLS_KEY_PATH"`
}

// maxBodyLimit is the largest NOOK_HTTP_MAX_BODY_BYTES accepted. API
// payloads are JSON; large artifacts (build contexts) go to object storage.
const maxBodyLimit = 64 << 20

// Validate checks addresses, timeouts and limits.
func (c *Config) Validate() error {
	errs := []error{
		config.CheckListenAddr("NOOK_HTTP_ADDR", c.Addr),
		config.CheckDuration("NOOK_HTTP_READ_HEADER_TIMEOUT", c.ReadHeaderTimeout, 100*time.Millisecond, time.Minute),
		config.CheckDuration("NOOK_HTTP_READ_TIMEOUT", c.ReadTimeout, 100*time.Millisecond, 10*time.Minute),
		config.CheckDuration("NOOK_HTTP_WRITE_TIMEOUT", c.WriteTimeout, 100*time.Millisecond, 10*time.Minute),
		config.CheckDuration("NOOK_HTTP_IDLE_TIMEOUT", c.IdleTimeout, time.Second, 10*time.Minute),
		config.CheckDuration("NOOK_HTTP_REQUEST_TIMEOUT", c.RequestTimeout, 100*time.Millisecond, 10*time.Minute),
		config.CheckDuration("NOOK_HTTP_SHUTDOWN_TIMEOUT", c.ShutdownTimeout, 0, 10*time.Minute),
		config.CheckRange[int64]("NOOK_HTTP_MAX_BODY_BYTES", c.MaxBodyBytes, 1, maxBodyLimit),
	}
	if c.RequestTimeout >= c.WriteTimeout {
		errs = append(errs, fmt.Errorf("NOOK_HTTP_REQUEST_TIMEOUT (%s) must be shorter than NOOK_HTTP_WRITE_TIMEOUT (%s)",
			c.RequestTimeout, c.WriteTimeout))
	}
	if c.ReadHeaderTimeout > c.ReadTimeout {
		errs = append(errs, fmt.Errorf("NOOK_HTTP_READ_HEADER_TIMEOUT (%s) must not exceed NOOK_HTTP_READ_TIMEOUT (%s)",
			c.ReadHeaderTimeout, c.ReadTimeout))
	}
	for _, p := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(p); err != nil {
			errs = append(errs, fmt.Errorf("NOOK_HTTP_TRUSTED_PROXIES: %q is not an IP address or CIDR", p))
		}
	}
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		errs = append(errs, errors.New("NOOK_HTTP_TLS_CERT_PATH and NOOK_HTTP_TLS_KEY_PATH must be set together"))
	}
	return errors.Join(errs...)
}

// TLSEnabled reports whether the server serves HTTPS.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertPath != "" && c.TLSKeyPath != ""
}
