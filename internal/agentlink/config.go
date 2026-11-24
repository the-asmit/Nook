package agentlink

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config configures the agent-facing gRPC endpoint.
type Config struct {
	// Addr is the gRPC listen address, separate from the REST API.
	Addr string `env:"NOOK_GRPC_ADDR" envDefault:":9443"`
	// PublicAddr is the host:port agents dial; it is printed in join
	// commands and is always covered by the server certificate. Default:
	// the NOOK_PUBLIC_URL host with the NOOK_GRPC_ADDR port.
	PublicAddr string `env:"NOOK_GRPC_PUBLIC_ADDR"`
	// ExtraNames are more host names or IPs for the server certificate,
	// e.g. every control-plane instance's own address.
	ExtraNames []string `env:"NOOK_GRPC_SERVER_NAMES" envSeparator:","`
	// CAPath is the CA bundle (certificate + key, mode 0600). It is created
	// on first start; every control-plane instance must use the same one.
	CAPath string `env:"NOOK_PKI_CA_PATH" envDefault:"/var/lib/nook-server/pki/ca.pem"`
}

// Validate checks addresses and names.
func (c *Config) Validate() error {
	var errs []error
	if err := config.CheckListenAddr("NOOK_GRPC_ADDR", c.Addr); err != nil {
		errs = append(errs, err)
	}
	if c.PublicAddr != "" {
		if host, port, err := net.SplitHostPort(c.PublicAddr); err != nil || host == "" || !validPort(port) {
			errs = append(errs, fmt.Errorf("NOOK_GRPC_PUBLIC_ADDR: must be host:port, got %q", c.PublicAddr))
		}
	}
	for _, n := range c.ExtraNames {
		if n == "" || len(n) > 253 {
			errs = append(errs, fmt.Errorf("NOOK_GRPC_SERVER_NAMES: invalid name %q", n))
		}
	}
	if c.CAPath == "" {
		errs = append(errs, errors.New("NOOK_PKI_CA_PATH must not be empty"))
	}
	return errors.Join(errs...)
}

func validPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n > 0 && n < 65536
}

// ResolvePublicAddr returns PublicAddr, or the default derived from the
// public URL's host and the listen port.
func (c *Config) ResolvePublicAddr(publicHost string) string {
	if c.PublicAddr != "" {
		return c.PublicAddr
	}
	_, port, _ := net.SplitHostPort(c.Addr)
	return net.JoinHostPort(publicHost, port)
}

// CertificateNames returns the names the server certificate must cover.
func (c *Config) CertificateNames(publicHost string) []string {
	host, _, _ := net.SplitHostPort(c.ResolvePublicAddr(publicHost))
	names := []string{host}
	for _, n := range c.ExtraNames {
		if n != host {
			names = append(names, n)
		}
	}
	return names
}
