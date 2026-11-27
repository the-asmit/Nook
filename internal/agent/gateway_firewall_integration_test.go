//go:build integration

package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/testinfra"
)

// The "LAN" the gateway and another host share with the node (the node
// routes between it and the app's bridge).
const (
	lanSubnet  = "203.0.113.0/24"
	gatewayIP  = "203.0.113.10"
	outsiderIP = "203.0.113.20"
)

// TestAppPortsAcceptOnlyTheGateways runs an app container on a bridge
// like the agent's and connects to the app's port from two hosts on
// another network that routes to the node: without the firewall both get
// in; with NOOK_AGENT_GATEWAY_ADDRS set only the gateway does. In
// production the gateway connects to the port published on the node's
// address, which Docker DNATs to the container: the same FORWARD rule.
// The test connects to the container's address directly (Docker Desktop
// publishes ports outside its VM's iptables, and a native engine drops
// routed traffic to ports published on 127.0.0.1), so the app network
// allows direct routing (nat-unprotected) and nothing is published.
func TestAppPortsAcceptOnlyTheGateways(t *testing.T) {
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
	lan := "nook-test-lan-" + suffix
	appNet := "nook-test-app-" + suffix
	bridgePrefix := "nkt" + suffix
	createNetwork(t, d, lan, lanSubnet, nil)
	routed(t, lan)
	createNetwork(t, d, appNet, "", map[string]string{
		"com.docker.network.bridge.name": bridgePrefix + "0", "com.docker.network.bridge.enable_icc": "false",
		"com.docker.network.bridge.gateway_mode_ipv4": "nat-unprotected",
	})

	created, err := d.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: testinfra.BusyboxImage, User: "65534:65534",
			Cmd: []string{"sh", "-c", "mkdir -p /tmp/www && echo app > /tmp/www/index.html && exec httpd -f -p 8080 -h /tmp/www"},
		},
		HostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(appNet), CapDrop: []string{"ALL"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.client.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{Force: true})
	})
	if _, err = d.client.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	info, err := d.client.ContainerInspect(ctx, created.ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ep, ok := info.Container.NetworkSettings.Networks[appNet]
	if !ok || !ep.IPAddress.IsValid() {
		t.Fatalf("the app container has no address on %s", appNet)
	}
	target := "http://" + ep.IPAddress.String() + ":8080/"

	fetch := func(from string) bool {
		t.Helper()
		return probeFrom(t, d, lan, from, target)
	}
	deadline := time.Now().Add(30 * time.Second)
	for !fetch(gatewayIP) {
		if time.Now().After(deadline) {
			t.Fatal("the app does not answer")
		}
	}
	if !fetch(outsiderIP) {
		t.Fatal("without the firewall another host cannot reach the app either; the test proves nothing")
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
			Chain: "NT" + strings.ToUpper(randomHex(t, 5)), AppBridge: bridgePrefix,
			Gateways: []netip.Prefix{netip.MustParsePrefix(gatewayIP + "/32")},
		},
	}
	if err := fw.apply(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fw.remove(context.Background()); err != nil {
			t.Errorf("remove the firewall: %v", err)
		}
	})
	if !fetch(gatewayIP) {
		t.Fatal("the gateway cannot reach the app through the firewall")
	}
	if fetch(outsiderIP) {
		t.Fatal("a host that is not a gateway reached the app's port")
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// createNetwork creates a bridge network removed after the test.
func createNetwork(t *testing.T, d *docker, name, subnet string, options map[string]string) {
	t.Helper()
	ctx := context.Background()
	opts := client.NetworkCreateOptions{Driver: "bridge", Options: options}
	if subnet != "" {
		opts.IPAM = &network.IPAM{Config: []network.IPAMConfig{{Subnet: netip.MustParsePrefix(subnet)}}}
	}
	if _, err := d.client.NetworkCreate(ctx, name, opts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.client.NetworkRemove(context.Background(), name, client.NetworkRemoveOptions{}) })
}

// routed lets traffic to and from a stand-in network pass Docker's
// isolation between networks (a native engine drops it), as on a real
// routed network; the firewall under test still filters it first.
func routed(t *testing.T, nw string) {
	t.Helper()
	undo, err := testinfra.AllowRouting(context.Background(), nw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(undo)
}

// probeFrom fetches target from a throwaway container at ip on nw.
func probeFrom(t *testing.T, d *docker, nw, ip, target string) bool {
	t.Helper()
	code, out, err := d.runOnce(context.Background(), client.ContainerCreateOptions{
		Config: &container.Config{Image: testinfra.BusyboxImage, User: "65534:65534", Cmd: []string{"wget", "-q", "-T", "3", "-O", "-", target}},
		HostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(nw), CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
		},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
			nw: {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: netip.MustParseAddr(ip)}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Logf("from %s: %s", ip, strings.TrimSpace(out))
	}
	return code == 0
}
