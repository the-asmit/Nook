package agent

import (
	"errors"
	"net/netip"

	"github.com/the-asmit/nook/internal/platform/config"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// DatabaseConfig configures how the node hosts the app database server
// when the control plane places it here.
type DatabaseConfig struct {
	// Addr is where app containers (on every node) reach the server:
	// default NOOK_AGENT_ADVERTISE_ADDR. "host-gateway" uses Docker's host
	// gateway, for development where the advertise address is loopback.
	Addr string `env:"NOOK_AGENT_DB_ADDR"`
	// PublishAddr is where the server's port is bound: default the address
	// app ports are bound to (NOOK_AGENT_PUBLISH_ADDR or the advertise
	// address).
	PublishAddr string `env:"NOOK_AGENT_DB_PUBLISH_ADDR"`
	// Port is the published port.
	Port int `env:"NOOK_AGENT_DB_PORT" envDefault:"5433"`
	// Network is the Docker network of the server container; the egress
	// firewall filters it.
	Network string `env:"NOOK_AGENT_DB_NETWORK" envDefault:"nook-db"`
	// ClientAddrs are the only remote addresses (IPs or CIDRs: the other
	// nodes and the control plane) that may connect to the server. Empty
	// means no restriction (the agent warns).
	ClientAddrs []string `env:"NOOK_AGENT_DB_CLIENT_ADDRS" envSeparator:","`
	// EgressAllow are private addresses the server may reach: the object
	// store its backups go to, when that is on a private network.
	EgressAllow []string `env:"NOOK_AGENT_DB_EGRESS_ALLOW" envSeparator:","`
}

func (c *DatabaseConfig) validate(allowPublic bool) error {
	var errs []error
	if c.Addr != "" && c.Addr != hostGateway {
		if a, err := netip.ParseAddr(c.Addr); err != nil || a.IsUnspecified() || a.IsMulticast() {
			errs = append(errs, errors.New("NOOK_AGENT_DB_ADDR must be an IP address app containers reach the node at, or host-gateway"))
		} else if !privateAdvertise(a) && !allowPublic {
			errs = append(errs, publicAddrError("NOOK_AGENT_DB_ADDR", a))
		}
	}
	if c.PublishAddr != "" {
		if a, err := netip.ParseAddr(c.PublishAddr); err != nil || a.IsUnspecified() || a.IsMulticast() {
			errs = append(errs, errors.New("NOOK_AGENT_DB_PUBLISH_ADDR must be an IP address of the node (not 0.0.0.0 or ::)"))
		} else if !privateAdvertise(a) && !allowPublic {
			errs = append(errs, publicAddrError("NOOK_AGENT_DB_PUBLISH_ADDR", a))
		}
	}
	errs = append(errs, config.CheckRange("NOOK_AGENT_DB_PORT", c.Port, 1, 65535))
	if !networkNamePattern.MatchString(c.Network) {
		errs = append(errs, errors.New("NOOK_AGENT_DB_NETWORK must be a network name (lower-case letters, digits, '.', '_', '-')"))
	}
	if _, err := parsePrefixes("NOOK_AGENT_DB_CLIENT_ADDRS", c.ClientAddrs); err != nil {
		errs = append(errs, err)
	}
	if _, err := parsePrefixes("NOOK_AGENT_DB_EGRESS_ALLOW", c.EgressAllow); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// describe adds what the node offers for the database server to info.
func (d *databases) describe(info *agentv1.NodeInfo) {
	if d.unavailable != "" {
		info.DatabaseUnavailableReason = d.unavailable
		return
	}
	info.DatabaseAddress = d.addr.String()
	info.DatabasePublishAddress = d.publish.String()
	info.DatabasePort = int32(d.port) //nolint:gosec // G115: a validated port.
}
