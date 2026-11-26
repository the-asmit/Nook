// Package gateway is nook-gateway, the only public entry point: it serves
// every app at https://<app>--<workspace>.<apps domain> and the auth host
// at auth.<apps domain>. It keeps a route table (loaded from the control
// plane's internal API, updated from Redis Pub/Sub, resynced
// periodically), signs visitors in through the auth host, checks each
// app's access policy and reverse-proxies to the app's instance on its
// node. It holds no database credentials and no OIDC secret: the control
// plane decides, the gateway enforces.
package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/logging"
	"github.com/the-asmit/nook/internal/platform/redis"
	"github.com/the-asmit/nook/internal/routes"
)

// TLS modes.
const (
	// TLSACME obtains certificates from an ACME CA (Let's Encrypt) on
	// demand, for known hosts only.
	TLSACME = "acme"
	// TLSFiles serves a certificate and key supplied by the operator.
	TLSFiles = "files"
	// TLSProxy serves plain HTTP behind a trusted TLS-terminating proxy.
	TLSProxy = "proxy"
	// TLSOff serves plain HTTP (development on *.localhost only).
	TLSOff = "off"
)

// Config configures nook-gateway.
type Config struct {
	Environment config.Environment `env:"NOOK_ENV,required,notEmpty"`
	Log         logging.Config
	Redis       redis.Config
	// AppsBaseURL is the apps domain with scheme and port, the same value
	// the control plane uses.
	AppsBaseURL string `env:"NOOK_APPS_BASE_URL,required,notEmpty"`
	// ControlPlaneURL is the control plane's internal address.
	ControlPlaneURL string `env:"NOOK_GATEWAY_CONTROL_PLANE_URL,required,notEmpty"`
	// Secret authenticates the gateway on the control plane.
	Secret config.Secret `env:"NOOK_GATEWAY_SECRET,required,notEmpty"`
	// AllowPlaintextInternal permits an http:// control plane on an
	// internal host outside development.
	AllowPlaintextInternal bool `env:"NOOK_ALLOW_PLAINTEXT_INTERNAL" envDefault:"false"`

	TLSMode string `env:"NOOK_GATEWAY_TLS_MODE" envDefault:"acme"`
	// HTTPAddr serves HTTP: ACME HTTP-01 and redirects to HTTPS, or the
	// whole gateway in proxy and off modes.
	HTTPAddr string `env:"NOOK_GATEWAY_HTTP_ADDR" envDefault:":80"`
	// HTTPSAddr serves HTTPS (acme and files modes).
	HTTPSAddr   string `env:"NOOK_GATEWAY_HTTPS_ADDR" envDefault:":443"`
	TLSCertPath string `env:"NOOK_GATEWAY_TLS_CERT_PATH"`
	TLSKeyPath  string `env:"NOOK_GATEWAY_TLS_KEY_PATH"`
	// ACMEEmail is the contact for the CA account.
	ACMEEmail string `env:"NOOK_GATEWAY_ACME_EMAIL"`
	// ACMEDirectoryURL defaults to Let's Encrypt production.
	ACMEDirectoryURL string `env:"NOOK_GATEWAY_ACME_DIRECTORY_URL" envDefault:"https://acme-v02.api.letsencrypt.org/directory"`
	// TrustedProxies are the TLS-terminating proxies (proxy mode) whose
	// X-Forwarded-For the gateway believes.
	TrustedProxies []string `env:"NOOK_GATEWAY_TRUSTED_PROXIES" envSeparator:","`

	// OpsAddr serves /healthz, /readyz and /metrics; keep it internal.
	OpsAddr string `env:"NOOK_GATEWAY_OPS_ADDR" envDefault:"127.0.0.1:9102"`
	// ResyncInterval bounds how long a missed route event goes unnoticed.
	ResyncInterval time.Duration `env:"NOOK_GATEWAY_RESYNC_INTERVAL" envDefault:"30s"`
	// AccessCacheTTL is how long an access decision is reused; revoking
	// access takes effect within it.
	AccessCacheTTL time.Duration `env:"NOOK_GATEWAY_ACCESS_CACHE_TTL" envDefault:"30s"`
	// MaxBodyBytes limits a request body.
	MaxBodyBytes int64 `env:"NOOK_GATEWAY_MAX_BODY_BYTES" envDefault:"104857600"`
	// UpstreamHeaderTimeout bounds waiting for an app's response headers.
	UpstreamHeaderTimeout time.Duration `env:"NOOK_GATEWAY_UPSTREAM_HEADER_TIMEOUT" envDefault:"60s"`
	// Rate limits (requests per second and burst), per gateway instance.
	RatePerIP    float64       `env:"NOOK_GATEWAY_RATE_PER_IP" envDefault:"50"`
	BurstPerIP   int           `env:"NOOK_GATEWAY_BURST_PER_IP" envDefault:"100"`
	RatePerApp   float64       `env:"NOOK_GATEWAY_RATE_PER_APP" envDefault:"500"`
	BurstPerApp  int           `env:"NOOK_GATEWAY_BURST_PER_APP" envDefault:"1000"`
	DrainTimeout time.Duration `env:"NOOK_GATEWAY_DRAIN_TIMEOUT" envDefault:"30s"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	errs := []error{c.Log.Validate(), c.Redis.Validate()}
	if err := c.Environment.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("NOOK_ENV: %w", err))
	}
	base, err := routes.ParseBase(c.AppsBaseURL)
	if err != nil {
		errs = append(errs, fmt.Errorf("NOOK_APPS_BASE_URL: %w", err))
	}
	cp, err := url.Parse(c.ControlPlaneURL)
	if err != nil || (cp.Scheme != "http" && cp.Scheme != "https") || cp.Host == "" {
		errs = append(errs, errors.New("NOOK_GATEWAY_CONTROL_PLANE_URL: must be an http(s):// URL"))
	} else if cp.Scheme == "http" && !c.Environment.IsDevelopment() && (!c.AllowPlaintextInternal || !config.IsInternalHost(cp.Hostname())) {
		errs = append(errs, errors.New("NOOK_GATEWAY_CONTROL_PLANE_URL: https:// is required outside development (or an internal host with NOOK_ALLOW_PLAINTEXT_INTERNAL=true)"))
	}
	if len(c.Secret.Reveal()) < 32 {
		errs = append(errs, errors.New("NOOK_GATEWAY_SECRET: at least 32 characters required"))
	}
	errs = append(errs, c.validateTLS(base))
	if _, err := c.trustedProxies(); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs,
		config.CheckListenAddr("NOOK_GATEWAY_OPS_ADDR", c.OpsAddr),
		config.CheckDuration("NOOK_GATEWAY_RESYNC_INTERVAL", c.ResyncInterval, 100*time.Millisecond, time.Hour),
		config.CheckDuration("NOOK_GATEWAY_ACCESS_CACHE_TTL", c.AccessCacheTTL, 0, 10*time.Minute),
		config.CheckRange("NOOK_GATEWAY_MAX_BODY_BYTES", c.MaxBodyBytes, 1<<10, 10<<30),
		config.CheckDuration("NOOK_GATEWAY_UPSTREAM_HEADER_TIMEOUT", c.UpstreamHeaderTimeout, time.Second, time.Hour),
		config.CheckRange("NOOK_GATEWAY_RATE_PER_IP", c.RatePerIP, 0.1, 1e6),
		config.CheckRange("NOOK_GATEWAY_BURST_PER_IP", c.BurstPerIP, 1, 1_000_000),
		config.CheckRange("NOOK_GATEWAY_RATE_PER_APP", c.RatePerApp, 0.1, 1e7),
		config.CheckRange("NOOK_GATEWAY_BURST_PER_APP", c.BurstPerApp, 1, 10_000_000),
		config.CheckDuration("NOOK_GATEWAY_DRAIN_TIMEOUT", c.DrainTimeout, time.Second, 10*time.Minute),
	)
	return errors.Join(errs...)
}

func (c *Config) validateTLS(base routes.Base) error {
	var errs []error
	switch c.TLSMode {
	case TLSACME:
		if c.ACMEEmail == "" || !strings.Contains(c.ACMEEmail, "@") {
			errs = append(errs, errors.New("NOOK_GATEWAY_ACME_EMAIL: required in acme mode (the CA's contact)"))
		}
		if u, err := url.Parse(c.ACMEDirectoryURL); err != nil || u.Scheme != "https" {
			errs = append(errs, errors.New("NOOK_GATEWAY_ACME_DIRECTORY_URL: must be an https:// URL"))
		}
		errs = append(errs, config.CheckListenAddr("NOOK_GATEWAY_HTTP_ADDR", c.HTTPAddr), config.CheckListenAddr("NOOK_GATEWAY_HTTPS_ADDR", c.HTTPSAddr))
	case TLSFiles:
		if c.TLSCertPath == "" || c.TLSKeyPath == "" {
			errs = append(errs, errors.New("NOOK_GATEWAY_TLS_CERT_PATH and NOOK_GATEWAY_TLS_KEY_PATH: required in files mode"))
		}
		errs = append(errs, config.CheckListenAddr("NOOK_GATEWAY_HTTP_ADDR", c.HTTPAddr), config.CheckListenAddr("NOOK_GATEWAY_HTTPS_ADDR", c.HTTPSAddr))
	case TLSProxy:
		if len(c.TrustedProxies) == 0 {
			errs = append(errs, errors.New("NOOK_GATEWAY_TRUSTED_PROXIES: required in proxy mode (the proxies' addresses or CIDRs)"))
		}
		errs = append(errs, config.CheckListenAddr("NOOK_GATEWAY_HTTP_ADDR", c.HTTPAddr))
	case TLSOff:
		if !c.Environment.IsDevelopment() || !strings.HasSuffix(base.Domain, ".localhost") {
			errs = append(errs, errors.New("NOOK_GATEWAY_TLS_MODE=off: only for development on *.localhost"))
		}
		errs = append(errs, config.CheckListenAddr("NOOK_GATEWAY_HTTP_ADDR", c.HTTPAddr))
	default:
		errs = append(errs, fmt.Errorf("NOOK_GATEWAY_TLS_MODE: must be acme, files, proxy or off, got %q", c.TLSMode))
	}
	if c.TLSMode != TLSOff && base.Scheme != "https" && base.Domain != "" {
		errs = append(errs, errors.New("NOOK_APPS_BASE_URL: must be https:// unless NOOK_GATEWAY_TLS_MODE=off"))
	}
	if c.TLSMode == TLSOff && base.Scheme != "http" && base.Domain != "" {
		errs = append(errs, errors.New("NOOK_APPS_BASE_URL: must be http:// with NOOK_GATEWAY_TLS_MODE=off"))
	}
	return errors.Join(errs...)
}

// trustedProxies parses NOOK_GATEWAY_TRUSTED_PROXIES.
func (c *Config) trustedProxies() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range c.TrustedProxies {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("NOOK_GATEWAY_TRUSTED_PROXIES: %q is not an IP address or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// base returns the parsed apps base; meaningful on a validated Config.
func (c *Config) base() routes.Base {
	b, _ := routes.ParseBase(c.AppsBaseURL)
	return b
}
