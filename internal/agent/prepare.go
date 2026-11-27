package agent

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// buildSeccompProfile is Docker's default seccomp profile plus the system
// calls rootless BuildKit needs to create its user and mount namespaces
// (clone and unshare with namespace flags, setns, mount, umount2,
// pivot_root, keyctl, sethostname). Everything else Docker's default
// forbids stays forbidden. See the build-isolation ADR.
//
//go:embed seccomp_build.json
var buildSeccompProfile string

// notReadyError means the node cannot run containers yet or at all.
type notReadyError struct{ reason string }

func (e notReadyError) Error() string { return e.reason }

// firewallRetry paces installing the firewall while Docker is unreachable.
const firewallRetry = 10 * time.Second

// prepare readies the node: the build network, the egress firewall, the
// check that rootless BuildKit can run, leftover build cleanup, adoption
// of running app containers and the watcher of container exits.
func (a *Agent) prepare(ctx context.Context) error {
	a.instances.mu.Lock()
	a.instances.ctx = ctx
	a.instances.mu.Unlock()
	a.databases.mu.Lock()
	a.databases.ctx = ctx
	a.databases.mu.Unlock()

	if err := os.RemoveAll(a.instances.puller.tmpDir); err != nil {
		a.logger.WarnContext(ctx, "could not remove leftover image downloads", "error", err.Error())
	}
	if err := os.MkdirAll(a.instances.puller.tmpDir, 0o700); err != nil {
		return fmt.Errorf("create the image download directory: %w", err)
	}
	if a.cfg.BuildSlots > 0 {
		a.builder.removeOrphans(ctx)
		if err := a.docker.ensureBuildNetwork(ctx, a.cfg.BuildNetwork); err != nil {
			a.logger.WarnContext(ctx, "could not create the build network", "error", err.Error())
		}
	}
	spec, err := firewallSpecFor(&a.cfg)
	if err != nil {
		return err
	}
	fw := &firewall{docker: a.docker, image: a.cfg.FirewallImage, logger: a.logger, spec: spec}
	if a.cfg.EgressFilter {
		a.databases.fw = fw
	}
	a.databases.setup(ctx, &a.cfg, a.instances.advertise, a.instances.publish)
	if a.databases.unavailable != "" {
		a.logger.InfoContext(ctx, "this node cannot host the app database server", "reason", a.databases.unavailable)
	} else if len(spec.DBClients) == 0 {
		a.logger.WarnContext(ctx, "NOOK_AGENT_DB_CLIENT_ADDRS is not set: an app database server on this node accepts connections from anywhere on the node's network (passwords and TLS still apply)")
	}
	reapply := func(context.Context) {}
	if len(spec.Gateways) == 0 {
		a.logger.WarnContext(ctx, "NOOK_AGENT_GATEWAY_ADDRS is not set: app ports accept connections from anywhere on the node's network, not only the gateways")
	}
	if a.cfg.EgressFilter {
		// The engine came back: its DNS configuration may have changed too.
		reapply = func(ctx context.Context) {
			a.refreshResolvers(ctx, fw)
			if err := fw.apply(ctx); err != nil {
				a.logger.ErrorContext(ctx, "could not reinstall the egress firewall", "error", err.Error())
			}
		}
		a.refreshResolvers(ctx, fw)
		go a.watchResolvers(ctx, fw)
		// Builds use the same resolvers for RUN steps.
		a.builder.resolvers = fw.resolvers
		if err := fw.apply(ctx); err != nil {
			a.logger.ErrorContext(ctx, "egress firewall not installed yet; apps and builds wait for it", "error", err.Error())
			go a.installFirewall(ctx, fw)
		} else {
			a.firewallReady.Store(true)
		}
	} else {
		a.logger.WarnContext(ctx, "NOOK_AGENT_EGRESS_FILTER is off: apps and builds can reach cloud metadata and private networks")
		a.firewallReady.Store(true)
	}
	if a.cfg.BuildSlots > 0 {
		reason := a.probeBuilds(ctx)
		a.buildsUnavailable.Store(&reason)
		if reason != "" {
			a.logger.ErrorContext(ctx, "builds are unavailable on this node", "reason", reason)
		}
	}
	a.instances.adopt(ctx)
	a.databases.adopt(ctx)
	go a.instances.watch(ctx, reapply)
	return nil
}

// firewallSpecFor derives the egress rules from the configuration: app
// bridges always, the build bridge when the node builds.
func firewallSpecFor(cfg *Config) (firewallSpec, error) {
	allow, err := parsePrefixes("NOOK_AGENT_BUILD_EGRESS_ALLOW", cfg.BuildEgressAllow)
	if err != nil {
		return firewallSpec{}, err
	}
	block, err := parsePrefixes("NOOK_AGENT_EGRESS_BLOCK", cfg.EgressBlock)
	if err != nil {
		return firewallSpec{}, err
	}
	gateways, err := parsePrefixes("NOOK_AGENT_GATEWAY_ADDRS", cfg.GatewayAddrs)
	if err != nil {
		return firewallSpec{}, err
	}
	dbAllow, err := parsePrefixes("NOOK_AGENT_DB_EGRESS_ALLOW", cfg.Database.EgressAllow)
	if err != nil {
		return firewallSpec{}, err
	}
	dbClients, err := parsePrefixes("NOOK_AGENT_DB_CLIENT_ADDRS", cfg.Database.ClientAddrs)
	if err != nil {
		return firewallSpec{}, err
	}
	spec := firewallSpec{
		Chain: cfg.FirewallChain, AppBridge: appBridgePrefix, BuildAllow: allow, Block: block, Gateways: gateways,
		DBBridge: dbBridge(cfg.Database.Network), DBAllow: dbAllow, DBClients: dbClients,
	}
	if cfg.BuildSlots > 0 {
		spec.BuildBridge = buildBridge(cfg.BuildNetwork)
	}
	return spec, nil
}

// FirewallRules returns the iptables rules the agent installs (IPv4 and
// IPv6, in iptables-restore format), for `nook-agent firewall rules`. The
// DNS resolvers are read from the node as the agent does; without Docker
// the rules are printed without them, with a note.
func FirewallRules(ctx context.Context, cfg *Config) (string, error) {
	spec, err := firewallSpecFor(cfg)
	if err != nil {
		return "", err
	}
	note := ""
	d, err := newDocker()
	if err == nil {
		defer func() { _ = d.close() }()
		spec.Resolvers, err = d.resolvers(ctx, cfg.FirewallImage)
	}
	if err != nil {
		note = "# DNS resolvers could not be read (" + err.Error() + "); the agent adds DNS rules for them at startup\n"
	}
	v4, v6 := spec.rules()
	return note + "# IPv4\n" + v4 + "# IPv6\n" + v6, nil
}

// RemoveFirewall deletes the agent's egress rules from the node, for
// `nook-agent firewall remove` when a node leaves Nook.
func RemoveFirewall(ctx context.Context, cfg *Config, logger *slog.Logger) error {
	d, err := newDocker()
	if err != nil {
		return err
	}
	defer func() { _ = d.close() }()
	spec, err := firewallSpecFor(cfg)
	if err != nil {
		return err
	}
	return (&firewall{docker: d, image: cfg.FirewallImage, logger: logger, spec: spec}).remove(ctx)
}

// installFirewall retries until the firewall is installed or ctx ends.
func (a *Agent) installFirewall(ctx context.Context, fw *firewall) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(firewallRetry):
		}
		if err := fw.apply(ctx); err == nil {
			a.firewallReady.Store(true)
			return
		}
	}
}

// containersReady reports whether app containers may run.
func (a *Agent) containersReady() error {
	if !a.firewallReady.Load() {
		return notReadyError{"the node's egress firewall is not installed yet"}
	}
	return nil
}

// buildsReady reports whether builds may run.
func (a *Agent) buildsReady() error {
	if err := a.containersReady(); err != nil {
		return err
	}
	if r := *a.buildsUnavailable.Load(); r != "" {
		return notReadyError{"builds are unavailable on this node: " + r}
	}
	return nil
}

// ensureBuildNetwork creates the build network unless it exists.
func (d *docker) ensureBuildNetwork(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	if _, err := d.client.NetworkInspect(ctx, name, client.NetworkInspectOptions{}); err == nil {
		return nil
	}
	enableIPv6 := false
	_, err := d.client.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge", EnableIPv6: &enableIPv6,
		Options: map[string]string{
			"com.docker.network.bridge.name":       buildBridge(name),
			"com.docker.network.bridge.enable_icc": "false",
		},
		Labels: map[string]string{ManagedLabel: "true"},
	})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("create %s: %w", name, err)
	}
	return nil
}

// probeScript prints the AppArmor user-namespace restriction (Ubuntu
// 23.10+) and tries what rootless BuildKit does first: create a user
// namespace with rootlesskit.
const probeScript = `r=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)
echo "apparmor_restrict_unprivileged_userns=$r"
rootlesskit true`

// userNSFix is the fix for the Ubuntu AppArmor restriction.
const userNSFix = "the kernel restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1, Ubuntu 23.10 and later). " +
	"Fix on the node: echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/60-nook-userns.conf && sudo sysctl --system, then restart nook-agent"

// probeBuilds checks that rootless BuildKit can run here, in a container
// with the same restrictions as a build, and returns why not ("" if it
// can).
func (a *Agent) probeBuilds(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, imagePullTimeout)
	defer cancel()
	if err := a.docker.ensureImage(ctx, a.cfg.BuildImage); err != nil {
		a.logger.WarnContext(ctx, "could not pull the BuildKit image to check builds", "error", err.Error())
		return "the BuildKit image could not be pulled; check the node's Docker engine and network"
	}
	pids := int64(64)
	code, out, err := a.docker.runOnce(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: a.cfg.BuildImage, User: buildUser, Entrypoint: []string{"sh", "-c", probeScript},
			Labels: map[string]string{buildNodeLabel: a.NodeID(), "nook.build.probe": "true"},
		},
		HostConfig: &container.HostConfig{
			NetworkMode: "none",
			CapDrop:     []string{"ALL"},
			CapAdd:      []string{"SETUID", "SETGID"},
			SecurityOpt: []string{"seccomp=" + buildSeccompProfile},
			Resources:   container.Resources{Memory: 256 << 20, PidsLimit: &pids},
		},
	})
	if err != nil {
		a.logger.WarnContext(ctx, "could not run the build check", "error", err.Error())
		return "the agent could not run its build check container"
	}
	return probeVerdict(code, out)
}

// probeVerdict turns the build check's exit code and output into the
// reason builds are unavailable ("" when they are available).
func probeVerdict(code int64, out string) string {
	if code == 0 {
		return ""
	}
	if strings.Contains(out, "apparmor_restrict_unprivileged_userns=1") {
		return userNSFix
	}
	return "rootless BuildKit cannot create a user namespace here (" + lastLine(out) +
		"); allow unprivileged user namespaces (user.max_user_namespaces > 0) and restart nook-agent"
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if len(l) > 200 {
		l = l[:200]
	}
	if l == "" {
		return "no output"
	}
	return l
}
