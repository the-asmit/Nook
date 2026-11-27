package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// The egress firewall keeps app and build containers away from what they
// must never reach: cloud metadata services, the node's private networks
// and other nodes. Public internet stays reachable.
//
// It is a set of iptables chains of Nook's own (<chain>-FWD and
// <chain>-IN), jumped to first from DOCKER-USER (or FORWARD when Docker
// has no DOCKER-USER chain) and INPUT. Docker never flushes DOCKER-USER
// or INPUT, so the rules survive Docker restarts; the agent installs them
// idempotently at startup and again whenever the Docker engine comes
// back, and `nook-agent firewall remove` deletes them. The agent may run
// in a container without host networking, so the rules are installed by
// a short-lived helper container (host network, NET_ADMIN and NET_RAW
// only) from a pinned image that ships iptables.

// Blocked destinations for app and build containers.
var (
	blockedV4 = []string{
		"0.0.0.0/8",      // "this network"
		"10.0.0.0/8",     // private
		"100.64.0.0/10",  // carrier-grade NAT (also cloud metadata on some providers)
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local, including 169.254.169.254 (cloud metadata)
		"172.16.0.0/12",  // private
		"192.0.0.0/24",   // IETF protocol assignments
		"192.168.0.0/16", // private
		"198.18.0.0/15",  // benchmarking
		"224.0.0.0/4",    // multicast
		"240.0.0.0/4",    // reserved
	}
	blockedV6 = []string{
		"::1/128",   // loopback
		"fc00::/7",  // unique local, including fd00:ec2::254 (cloud metadata)
		"fe80::/10", // link-local
		"ff00::/8",  // multicast
	}
)

var chainPattern = regexp.MustCompile(`^[A-Z][A-Z0-9-]{0,19}$`)

// firewallSpec is what the rules are made from.
type firewallSpec struct {
	Chain string
	// AppBridge matches the bridges of app networks (iptables "+" suffix).
	AppBridge string
	// BuildBridge is the bridge of the build network ("" if builds use no
	// bridge the agent can name).
	BuildBridge string
	// BuildAllow are destinations builds may reach although blocked (the
	// registry).
	BuildAllow []netip.Prefix
	// Block are extra blocked destinations (other nodes' public addresses).
	Block []netip.Prefix
	// Gateways are the only sources that may open connections to app
	// containers (empty: no restriction).
	Gateways []netip.Prefix
	// Resolvers are the DNS servers Docker and the node use (read from the
	// node, see resolvers.go). Containers may send DNS (UDP and TCP port
	// 53) to them even when they lie in a blocked range, and nothing else.
	Resolvers []netip.Addr
	// DBBridge is the bridge of the app database server's network; its
	// container is filtered like apps and builds.
	DBBridge string
	// DBAllow are destinations the database server may reach although
	// blocked (the object store its backups go to).
	DBAllow []netip.Prefix
	// DBClients are the only remote sources that may open connections to
	// the database server (empty: no restriction); this node's apps reach
	// it through DBEndpoint.
	DBClients []netip.Prefix
	// DBEndpoint is the current app database server (invalid: none). App
	// containers may connect to exactly this address and port, and to no
	// earlier server: a replaced (fenced) server is unreachable for apps.
	DBEndpoint netip.AddrPort
}

// rules renders iptables-restore input for IPv4 and IPv6. Each chain is
// declared (which flushes it with --noflush) and rebuilt, so applying
// twice gives the same result.
func (s *firewallSpec) rules() (v4, v6 string) {
	return s.render(false), s.render(true)
}

func (s *firewallSpec) render(v6 bool) string {
	fwd, in := s.Chain+"-FWD", s.Chain+"-IN"
	reject := "icmp-admin-prohibited"
	blocked := blockedV4
	if v6 {
		reject, blocked = "icmp6-adm-prohibited", blockedV6
	}
	for _, p := range s.Block {
		if p.Addr().Is6() == v6 {
			blocked = append(blocked, p.String())
		}
	}
	ifaces := []string{s.AppBridge + "+"}
	if s.BuildBridge != "" {
		ifaces = append(ifaces, s.BuildBridge)
	}
	if s.DBBridge != "" {
		ifaces = append(ifaces, s.DBBridge)
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("*filter")
	w(":%s - [0:0]", fwd)
	w(":%s - [0:0]", in)
	for _, chain := range []string{fwd, in} {
		// Replies to connections made to the app (the gateway, health
		// checks) always pass.
		w("-A %s -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN", chain)
		if s.BuildBridge != "" {
			for _, p := range s.BuildAllow {
				if p.Addr().Is6() == v6 {
					w("-A %s -i %s -d %s -j RETURN", chain, s.BuildBridge, p)
				}
			}
		}
		if s.DBBridge != "" {
			for _, p := range s.DBAllow {
				if p.Addr().Is6() == v6 {
					w("-A %s -i %s -d %s -j RETURN", chain, s.DBBridge, p)
				}
			}
		}
		// Apps reach the current database server, wherever it runs: the
		// match is on the address they connected to, before Docker's
		// port mapping rewrote it.
		if ep := s.DBEndpoint; ep.IsValid() && ep.Addr().Is6() == v6 {
			dst := netip.PrefixFrom(ep.Addr(), ep.Addr().BitLen())
			w("-A %s -i %s -p tcp -m conntrack --ctorigdst %s --ctorigdstport %d -j RETURN", chain, s.AppBridge+"+", dst, ep.Port())
		}
		// DNS to the resolvers Docker and the node use, which often sit in
		// blocked ranges (169.254.169.254 on Oracle Cloud, 169.254.169.253
		// on AWS, a router on 192.168.x). Only port 53: HTTP to the same
		// address (the metadata service) still meets the REJECTs below.
		for _, iface := range ifaces {
			for _, r := range s.Resolvers {
				if r.Is6() == v6 {
					w("-A %s -i %s -d %s -p udp --dport 53 -j RETURN", chain, iface, netip.PrefixFrom(r, r.BitLen()))
					w("-A %s -i %s -d %s -p tcp --dport 53 -j RETURN", chain, iface, netip.PrefixFrom(r, r.BitLen()))
				}
			}
		}
	}
	for _, iface := range ifaces {
		for _, dst := range blocked {
			w("-A %s -i %s -d %s -j REJECT --reject-with %s", fwd, iface, dst, reject)
		}
		// Nothing on the node itself is for containers.
		w("-A %s -i %s -j REJECT --reject-with %s", in, iface, reject)
	}
	// Apps are reached only through the gateways: new connections into
	// app bridges from anywhere else (other containers, other hosts) are
	// refused, so the identity headers the gateway sets can be trusted.
	if len(s.Gateways) > 0 {
		for _, p := range s.Gateways {
			if p.Addr().Is6() == v6 {
				w("-A %s -o %s -m conntrack --ctstate NEW -s %s -j RETURN", fwd, s.AppBridge+"+", p)
			}
		}
		w("-A %s -o %s -m conntrack --ctstate NEW -j REJECT --reject-with %s", fwd, s.AppBridge+"+", reject)
	}
	// The database server accepts new connections only from the listed
	// clients (other nodes' apps arrive with their node's address, and the
	// control plane); this node's apps were let through above.
	if s.DBBridge != "" && len(s.DBClients) > 0 {
		for _, p := range s.DBClients {
			if p.Addr().Is6() == v6 {
				w("-A %s -o %s -m conntrack --ctstate NEW -s %s -j RETURN", fwd, s.DBBridge, p)
			}
		}
		w("-A %s -o %s -m conntrack --ctstate NEW -j REJECT --reject-with %s", fwd, s.DBBridge, reject)
	}
	w("COMMIT")
	return b.String()
}

// firewallScript runs in the helper container. It picks the iptables
// backend Docker uses (nf_tables or legacy), loads the chains and inserts
// the jumps once; "remove" deletes jumps and chains. Rules arrive in
// environment variables (the helper's root file system is read-only).
const firewallScript = `set -eu
B=nft
nft_rules=$(iptables-nft-save -t filter 2>/dev/null || true)
case "$nft_rules" in
  *":DOCKER"*) ;;
  *) legacy_rules=$(iptables-legacy-save -t filter 2>/dev/null || true)
     case "$legacy_rules" in *":DOCKER"*) B=legacy ;; esac ;;
esac
F="$NOOK_CHAIN-FWD"
I="$NOOK_CHAIN-IN"
apply() {
  ipt="$1"; rules="$2"
  printf '%s\n' "$rules" | "$ipt-restore" --noflush
  parent=FORWARD
  if "$ipt" -S DOCKER-USER >/dev/null 2>&1; then parent=DOCKER-USER; fi
  "$ipt" -C "$parent" -j "$F" 2>/dev/null || "$ipt" -I "$parent" 1 -j "$F"
  "$ipt" -C INPUT -j "$I" 2>/dev/null || "$ipt" -I INPUT 1 -j "$I"
}
remove() {
  ipt="$1"
  for parent in DOCKER-USER FORWARD; do
    while "$ipt" -D "$parent" -j "$F" 2>/dev/null; do :; done
  done
  while "$ipt" -D INPUT -j "$I" 2>/dev/null; do :; done
  for c in "$F" "$I"; do
    "$ipt" -F "$c" 2>/dev/null || true
    "$ipt" -X "$c" 2>/dev/null || true
  done
}
case "$NOOK_MODE" in
  apply)
    apply "iptables-$B" "$NOOK_RULES4"
    if ! apply "ip6tables-$B" "$NOOK_RULES6"; then echo "warning: IPv6 rules not applied (IPv6 disabled?)" >&2; fi
    echo "applied with iptables-$B" ;;
  remove)
    remove "iptables-$B"
    remove "ip6tables-$B" || true
    echo "removed with iptables-$B" ;;
esac
`

// firewall installs and removes the egress rules. mu serializes applies
// (startup, Docker reconnects and resolver changes) and guards spec.
type firewall struct {
	docker *docker
	image  string
	logger *slog.Logger

	mu   sync.Mutex
	spec firewallSpec
}

// firewallTimeout bounds one helper run (including pulling its image).
const firewallTimeout = 5 * time.Minute

// apply installs or refreshes the rules.
func (f *firewall) apply(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v4, v6 := f.spec.rules()
	out, err := f.run(ctx, "apply", v4, v6)
	if err != nil {
		return fmt.Errorf("install the egress firewall: %w", err)
	}
	f.logger.InfoContext(ctx, "egress firewall installed", "chain", f.spec.Chain, "result", strings.TrimSpace(out))
	return nil
}

// setResolvers replaces the resolver allowances and reports whether they
// changed (the caller applies the rules then).
func (f *firewall) setResolvers(rs []netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if slices.Equal(f.spec.Resolvers, rs) {
		return false
	}
	f.spec.Resolvers = rs
	return true
}

// setDatabaseEndpoint replaces the database endpoint apps may reach and
// reports whether it changed (the caller applies the rules then).
func (f *firewall) setDatabaseEndpoint(ep netip.AddrPort) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.spec.DBEndpoint == ep {
		return false
	}
	f.spec.DBEndpoint = ep
	return true
}

// resolvers returns the resolvers the rules currently allow DNS to.
func (f *firewall) resolvers() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.spec.Resolvers)
}

// remove deletes the rules.
func (f *firewall) remove(ctx context.Context) error {
	if _, err := f.run(ctx, "remove", "", ""); err != nil {
		return fmt.Errorf("remove the egress firewall: %w", err)
	}
	return nil
}

func (f *firewall) run(ctx context.Context, mode, v4, v6 string) (string, error) {
	if !chainPattern.MatchString(f.spec.Chain) {
		return "", errors.New("invalid chain name")
	}
	ctx, cancel := context.WithTimeout(ctx, firewallTimeout)
	defer cancel()
	if err := f.docker.ensureImage(ctx, f.image); err != nil {
		return "", err
	}
	code, out, err := f.docker.runOnce(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image:      f.image,
			User:       "0:0",
			Entrypoint: []string{"/bin/sh", "-c", firewallScript},
			Env:        []string{"NOOK_MODE=" + mode, "NOOK_CHAIN=" + f.spec.Chain, "NOOK_RULES4=" + v4, "NOOK_RULES6=" + v6},
			Labels:     map[string]string{"nook.firewall": "true"},
		},
		HostConfig: &container.HostConfig{
			NetworkMode:    "host",
			CapDrop:        []string{"ALL"},
			CapAdd:         []string{"NET_ADMIN", "NET_RAW"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			ReadonlyRootfs: true,
		},
	})
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("helper exited with code %d: %s", code, strings.TrimSpace(out))
	}
	return out, nil
}
