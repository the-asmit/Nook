package httpserver

import (
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		Addr:              "127.0.0.1:0",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		RequestTimeout:    20 * time.Second,
		ShutdownTimeout:   20 * time.Second,
		MaxBodyBytes:      1 << 20,
	}
}

func TestConfigValidateAcceptsDefaults(t *testing.T) {
	c := validConfig()
	c.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.10", "::1"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestConfigValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"bad addr", func(c *Config) { c.Addr = "8080" }, "NOOK_HTTP_ADDR"},
		{"zero read header timeout", func(c *Config) { c.ReadHeaderTimeout = 0 }, "NOOK_HTTP_READ_HEADER_TIMEOUT"},
		{"request timeout not below write timeout", func(c *Config) { c.RequestTimeout = c.WriteTimeout }, "must be shorter than NOOK_HTTP_WRITE_TIMEOUT"},
		{"header timeout above read timeout", func(c *Config) { c.ReadHeaderTimeout = 20 * time.Second }, "must not exceed NOOK_HTTP_READ_TIMEOUT"},
		{"body too large", func(c *Config) { c.MaxBodyBytes = maxBodyLimit + 1 }, "NOOK_HTTP_MAX_BODY_BYTES"},
		{"body zero", func(c *Config) { c.MaxBodyBytes = 0 }, "NOOK_HTTP_MAX_BODY_BYTES"},
		{"bad proxy", func(c *Config) { c.TrustedProxies = []string{"not-an-ip"} }, "NOOK_HTTP_TRUSTED_PROXIES"},
		{"cert without key", func(c *Config) { c.TLSCertPath = "/tmp/cert.pem" }, "must be set together"},
		{"negative shutdown", func(c *Config) { c.ShutdownTimeout = -time.Second }, "NOOK_HTTP_SHUTDOWN_TIMEOUT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestTLSEnabled(t *testing.T) {
	c := validConfig()
	if c.TLSEnabled() {
		t.Error("TLS should be off without paths")
	}
	c.TLSCertPath, c.TLSKeyPath = "cert.pem", "key.pem"
	if !c.TLSEnabled() {
		t.Error("TLS should be on with both paths")
	}
}
