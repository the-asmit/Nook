//go:build integration

package agent

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/testinfra"
)

// A link-local "metadata" network like Oracle Cloud's, where the resolver
// and the metadata service share an address. (Not 169.254.169.0/24: the
// server package's tests use that one and run in parallel.)
const (
	linkLocalSubnet = "169.254.170.0/24"
	resolverIP      = "169.254.170.254" // DNS on 53/udp, a listener on 53/tcp, HTTP on 80
	otherDNSIP      = "169.254.170.10"  // the same services, but not a resolver of the node
)

// standInCmd serves nook.test → 10.9.8.7 over DNS, plus TCP on 53 and HTTP on 80.
const standInCmd = `echo "nook.test 10.9.8.7" > /tmp/dnsd.conf && mkdir -p /tmp/www && echo metadata > /tmp/www/index.html && ` +
	`httpd -p 80 -h /tmp/www && httpd -p 53 -h /tmp/www && exec dnsd -c /tmp/dnsd.conf -p 53`

// TestDNSReachesOnlyTheResolvers installs the real rules with a resolver
// in the blocked link-local range and probes from an app bridge and a
// build bridge: DNS over UDP and TCP to the resolver works, HTTP to the
// same address stays blocked, and DNS to another link-local address is
// refused. Without the rules all of it is reachable, which shows the
// difference is the firewall.
func TestDNSReachesOnlyTheResolvers(t *testing.T) {
	ctx := context.Background()
	d, err := newDocker()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.close() })
	if err = d.ensureImage(ctx, testinfra.BusyboxImage); err != nil {
		t.Fatal(err)
	}
	suffix := randomHex(t, 3)
	lan := "nook-test-linklocal-" + suffix
	createNetwork(t, d, lan, linkLocalSubnet, map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "nat-unprotected"})
	for _, ip := range []string{resolverIP, otherDNSIP} {
		startDNSStandIn(t, d, lan, ip)
	}
	appBridge, buildBridgeName := "nkt"+suffix, "nkr"+suffix
	appNet, buildNet := "nook-test-app-"+suffix, "nook-test-build-"+suffix
	createNetwork(t, d, appNet, "", map[string]string{"com.docker.network.bridge.name": appBridge + "0"})
	createNetwork(t, d, buildNet, "", map[string]string{"com.docker.network.bridge.name": buildBridgeName})

	probes := map[string]string{
		"dns":       "nslookup nook.test " + resolverIP + " | grep -q 10.9.8.7",
		"dns-tcp":   "nc -z -w 3 " + resolverIP + " 53",
		"http":      "wget -q -T 3 -O - http://" + resolverIP + "/",
		"other-dns": "nslookup nook.test " + otherDNSIP + " | grep -q 10.9.8.7",
	}
	run := func(nw, name string) bool {
		t.Helper()
		code, _, runErr := d.runOnce(ctx, client.ContainerCreateOptions{
			Config: &container.Config{Image: testinfra.BusyboxImage, User: "65534:65534", Cmd: []string{"sh", "-c", probes[name]}},
			HostConfig: &container.HostConfig{
				NetworkMode: container.NetworkMode(nw), CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			},
		})
		if runErr != nil {
			t.Fatal(runErr)
		}
		return code == 0
	}
	// The stand-ins start in the background: wait until they answer.
	deadline := time.Now().Add(30 * time.Second)
	for !run(appNet, "dns") || !run(appNet, "http") {
		if time.Now().After(deadline) {
			t.Fatal("the DNS stand-in does not answer")
		}
	}
	for _, nw := range []string{appNet, buildNet} {
		for name := range probes {
			if !run(nw, name) {
				t.Fatalf("without the firewall, %s fails from %s; the test proves nothing", name, nw)
			}
		}
	}

	cfg, err := config.Load[Config](map[string]string{
		"NOOK_AGENT_STATE_DIR": filepath.Join(t.TempDir(), "agent"), "NOOK_AGENT_ADVERTISE_ADDR": "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	fw := &firewall{
		docker: d, image: cfg.FirewallImage, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		spec: firewallSpec{
			Chain: "NT" + strings.ToUpper(randomHex(t, 5)), AppBridge: appBridge, BuildBridge: buildBridgeName,
			Resolvers: []netip.Addr{netip.MustParseAddr(resolverIP)},
		},
	}
	if err = fw.apply(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fw.remove(context.Background()); err != nil {
			t.Errorf("remove the firewall: %v", err)
		}
	})
	want := map[string]bool{"dns": true, "dns-tcp": true, "http": false, "other-dns": false}
	for _, nw := range []string{appNet, buildNet} {
		for name, ok := range want {
			if got := run(nw, name); got != ok {
				t.Errorf("from %s with the firewall: %s succeeded = %v, want %v", nw, name, got, ok)
			}
		}
	}
}

// TestResolversAreReadFromTheNode: the agent reads the DNS servers that
// Docker hands containers (the default bridge's resolv.conf) and the
// node's own.
func TestResolversAreReadFromTheNode(t *testing.T) {
	ctx := context.Background()
	d, err := newDocker()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.close() })
	cfg, err := config.Load[Config](map[string]string{
		"NOOK_AGENT_STATE_DIR": filepath.Join(t.TempDir(), "agent"), "NOOK_AGENT_ADVERTISE_ADDR": "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.resolvers(ctx, cfg.FirewallImage)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ensureImage(ctx, testinfra.BusyboxImage); err != nil {
		t.Fatal(err)
	}
	var want [][]netip.Addr
	for _, mode := range []string{"bridge", "host"} {
		code, out, err := d.runOnce(ctx, client.ContainerCreateOptions{
			Config:     &container.Config{Image: testinfra.BusyboxImage, Cmd: []string{"cat", "/etc/resolv.conf"}},
			HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(mode)},
		})
		if err != nil || code != 0 {
			t.Fatalf("read resolv.conf on %s: %d %v", mode, code, err)
		}
		want = append(want, parseResolvConf(out))
	}
	if merged := mergeResolvers(want...); !slices.Equal(got, merged) || len(got) == 0 {
		t.Fatalf("resolvers = %v, want %v (non-empty)", got, merged)
	}
	t.Logf("this node's container resolvers: %v", got)
}

// startDNSStandIn runs the DNS/HTTP stand-in at ip on nw until the test ends.
func startDNSStandIn(t *testing.T, d *docker, nw, ip string) {
	t.Helper()
	ctx := context.Background()
	created, err := d.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     &container.Config{Image: testinfra.BusyboxImage, Cmd: []string{"sh", "-c", standInCmd}},
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(nw)},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
			nw: {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: netip.MustParseAddr(ip)}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.client.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{Force: true})
	})
	if _, err := d.client.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
}
