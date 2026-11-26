package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// The egress firewall allows DNS only to the resolvers containers actually
// use. They are read from the node rather than configured: Docker gives
// containers its "external" DNS servers (the daemon's --dns, else the
// host's resolv.conf without loopback entries), and its embedded resolver
// (127.0.0.11, on user-defined networks such as app and build networks)
// forwards to those same servers. A container on the default bridge
// network therefore shows them in its /etc/resolv.conf; a container on the
// host network shows the node's own. The union of both is allowed.

// resolverRefresh is how often the resolvers are read again (DHCP may
// change them; so may an edited daemon.json after a Docker restart, which
// also triggers a refresh through the event stream).
const resolverRefresh = 5 * time.Minute

// maxResolvers bounds the allowances (resolv.conf honors three anyway).
const maxResolvers = 16

// resolverScript prints /etc/resolv.conf with shell built-ins only (the
// helper image has a shell but no coreutils).
const resolverScript = `while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "$l"; done < /etc/resolv.conf`

// parseResolvConf returns the usable nameserver addresses of a resolv.conf:
// loopback servers (systemd-resolved's 127.0.0.53, Docker's 127.0.0.11)
// are unreachable from containers and skipped, as are unspecified and
// multicast ones. IPv6 zones are dropped (iptables matches addresses).
func parseResolvConf(text string) []netip.Addr {
	var out []netip.Addr
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		a = a.Unmap().WithZone("")
		if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		out = append(out, a)
	}
	return out
}

// mergeResolvers sorts and de-duplicates resolver lists, keeping at most
// maxResolvers.
func mergeResolvers(lists ...[]netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, l := range lists {
		out = append(out, l...)
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	out = slices.Compact(out)
	if len(out) > maxResolvers {
		out = out[:maxResolvers]
	}
	return out
}

// resolvers reads the DNS servers containers use (see above) with short
// helper containers from image (the firewall helper's, already pulled).
// It fails only when neither view could be read.
func (d *docker) resolvers(ctx context.Context, image string) ([]netip.Addr, error) {
	if err := d.ensureImage(ctx, image); err != nil {
		return nil, err
	}
	var lists [][]netip.Addr
	var errs []error
	for _, mode := range []container.NetworkMode{"bridge", "host"} {
		runCtx, cancel := context.WithTimeout(ctx, dockerTimeout)
		code, out, err := d.runOnce(runCtx, client.ContainerCreateOptions{
			Config: &container.Config{
				Image: image, User: "65534:65534", Entrypoint: []string{"/bin/sh", "-c", resolverScript},
				Labels: map[string]string{"nook.firewall": "true"},
			},
			HostConfig: &container.HostConfig{
				NetworkMode: mode, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, ReadonlyRootfs: true,
			},
		})
		cancel()
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s network: %w", mode, err))
		case code != 0:
			errs = append(errs, fmt.Errorf("%s network: reading resolv.conf exited with %d", mode, code))
		default:
			lists = append(lists, parseResolvConf(out))
		}
	}
	if len(lists) == 0 {
		return nil, fmt.Errorf("read the DNS resolvers: %w", errors.Join(errs...))
	}
	return mergeResolvers(lists...), nil
}

// refreshResolvers reads the resolvers into fw's rules and reports whether
// they changed. A failed read keeps the previous ones.
func (a *Agent) refreshResolvers(ctx context.Context, fw *firewall) bool {
	rs, err := a.docker.resolvers(ctx, a.cfg.FirewallImage)
	if err != nil {
		a.logger.WarnContext(ctx, "could not read the DNS resolvers; keeping the previous DNS allowances", "error", err.Error())
		return false
	}
	if !fw.setResolvers(rs) {
		return false
	}
	names := make([]string, len(rs))
	for i, r := range rs {
		names[i] = r.String()
	}
	a.logger.InfoContext(ctx, "DNS resolvers for containers", "resolvers", strings.Join(names, ","))
	return true
}

// watchResolvers re-reads the resolvers periodically and re-applies the
// rules when they change.
func (a *Agent) watchResolvers(ctx context.Context, fw *firewall) {
	t := time.NewTicker(resolverRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if a.refreshResolvers(ctx, fw) {
				if err := fw.apply(ctx); err != nil {
					a.logger.ErrorContext(ctx, "could not update the egress firewall for new DNS resolvers", "error", err.Error())
				}
			}
		}
	}
}
