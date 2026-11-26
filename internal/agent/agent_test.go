package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/moby/moby/api/types/network"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/config"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

func TestBackoffStaysWithinBounds(t *testing.T) {
	minD, maxD := 100*time.Millisecond, 5*time.Second
	for attempt := range 40 {
		for range 20 {
			d := backoff(attempt, minD, maxD)
			ceiling := maxD
			if attempt < 30 {
				ceiling = min(maxD, minD<<attempt)
			}
			if d < minD/2 || d > ceiling {
				t.Fatalf("attempt %d: %s outside [%s, %s]", attempt, d, minD/2, ceiling)
			}
		}
	}
}

func TestRenewDueAfterTwoThirds(t *testing.T) {
	start := time.Now()
	c := &x509.Certificate{NotBefore: start, NotAfter: start.Add(9 * time.Hour)}
	if renewDue(c, start.Add(5*time.Hour)) {
		t.Fatal("renewed too early")
	}
	if !renewDue(c, start.Add(6*time.Hour+time.Second)) {
		t.Fatal("not renewed after two thirds")
	}
}

func TestStateDirRoundTripAndPermissions(t *testing.T) {
	dir := stateDir(filepath.Join(t.TempDir(), "state"))
	if _, err := dir.load(); !errors.Is(err, ErrNotJoined) {
		t.Fatalf("empty dir: %v", err)
	}
	ca, _, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := newKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	id := mustUUID(t)
	issued, err := ca.SignNodeCSR(csr, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = dir.save(&identity{NodeID: id.String(), Name: "n1", Server: "127.0.0.1:9443", cert: issued.Cert, key: key, ca: ca.Certificate()}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{stateFile, identityFile, caFile} {
		info, statErr := os.Stat(dir.path(f))
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, info, statErr)
		}
	}
	got, err := dir.load()
	if err != nil || got.NodeID != id.String() || !got.cert.Equal(issued.Cert) {
		t.Fatalf("load: %v", err)
	}
	if !dir.joined() {
		t.Fatal("joined() false after save")
	}

	if err := os.Chmod(string(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.load(); err == nil || !strings.Contains(err.Error(), "must be 0700") {
		t.Fatalf("loose directory accepted: %v", err)
	}
	_ = os.Chmod(string(dir), 0o700)
	if err := os.Chmod(dir.path(identityFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.load(); !errors.Is(err, pki.ErrInsecurePermissions) {
		t.Fatalf("loose key file accepted: %v", err)
	}
}

func TestPermanentErrors(t *testing.T) {
	if !permanent(status.Error(codes.PermissionDenied, "removed")) || !permanent(status.Error(codes.Unauthenticated, "x")) {
		t.Fatal("rejections must be permanent")
	}
	if permanent(status.Error(codes.Unavailable, "down")) || permanent(errors.New("plain")) {
		t.Fatal("transient errors must be retried")
	}
	if !isCAMismatch(errors.New("tls: "+pki.ErrCAMismatch.Error())) || isCAMismatch(nil) {
		t.Fatal("isCAMismatch")
	}
	if got := describeRPCError(status.Error(codes.Unavailable, "connection refused")); !strings.Contains(got.Error(), "cannot reach") {
		t.Fatalf("describe: %v", got)
	}
}

func TestConfigValidate(t *testing.T) {
	c, err := config.Load[Config](map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": "10.0.0.5"})
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if c.BuildSlots != 2 || !strings.Contains(c.BuildImage, "@sha256:") || c.BuildProxy || c.BuildNetwork != defaultBuildNetwork ||
		!c.EgressFilter || c.FirewallChain != "NOOK" || !strings.Contains(c.FirewallImage, "@sha256:") {
		t.Fatalf("defaults %+v", c)
	}
	for name, mutate := range map[string]func(*Config){
		"max below min":   func(c *Config) { c.ReconnectMax = time.Millisecond },
		"unpinned image":  func(c *Config) { c.BuildImage = "moby/buildkit:rootless" },
		"too many slots":  func(c *Config) { c.BuildSlots = 65 },
		"bad network":     func(c *Config) { c.BuildNetwork = "Not A Name" },
		"bad build host":  func(c *Config) { c.BuildHosts = []string{"registry:10.0.0.5"} },
		"bad build ip":    func(c *Config) { c.BuildHosts = []string{"registry=x"} },
		"tiny context":    func(c *Config) { c.BuildMaxContextBytes = 10 },
		"empty state dir": func(c *Config) { c.StateDir = "" },
		"no advertise":    func(c *Config) { c.AdvertiseAddr = "" },
		"wildcard v4":     func(c *Config) { c.AdvertiseAddr = "0.0.0.0" },
		"wildcard v6":     func(c *Config) { c.AdvertiseAddr = "::" },
		"public v4":       func(c *Config) { c.AdvertiseAddr = "203.0.113.7" },
		"public v6":       func(c *Config) { c.AdvertiseAddr = "2001:db8::7" },
		"link-local":      func(c *Config) { c.AdvertiseAddr = "169.254.10.1" },
		"bad chain":       func(c *Config) { c.FirewallChain = "nook; rm" },
		"unpinned fw":     func(c *Config) { c.FirewallImage = "registry.k8s.io/build-image/distroless-iptables:v0.9.6" },
		"bad allow":       func(c *Config) { c.BuildEgressAllow = []string{"registry.internal"} },
		"bad block":       func(c *Config) { c.EgressBlock = []string{"10.0.0.0/33"} },
		"bad pull addr":   func(c *Config) { c.RegistryPullAddr = "https://x" },
		"zero crashes":    func(c *Config) { c.CrashLimit = 0 },
		"backoff order":   func(c *Config) { c.RestartBackoffMax = time.Millisecond },
	} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestPublicAdvertiseAddressNeedsTheOverride: app traffic is plain HTTP,
// so the agent refuses a public advertise address unless told otherwise,
// and then warns.
func TestPublicAdvertiseAddressNeedsTheOverride(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "::1", "10.1.2.3", "172.31.250.1", "192.168.1.9", "100.101.102.103", "fd12:3456::1", "::ffff:10.0.0.1"} {
		c, err := config.Load[Config](map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": addr})
		if err != nil {
			t.Errorf("%s: %v", addr, err)
			continue
		}
		if w := publicAdvertiseWarning(&c); w != "" {
			t.Errorf("%s: unexpected warning %q", addr, w)
		}
	}
	for _, addr := range []string{"203.0.113.7", "8.8.8.8", "2001:db8::7", "100.128.0.1"} {
		_, err := config.Load[Config](map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": addr})
		if err == nil || !strings.Contains(err.Error(), "not a private address") || !strings.Contains(err.Error(), "NOOK_AGENT_ALLOW_PUBLIC_ADVERTISE_ADDR") {
			t.Errorf("%s: %v, want a refusal naming the override", addr, err)
		}
		c, err := config.Load[Config](map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": addr, "NOOK_AGENT_ALLOW_PUBLIC_ADVERTISE_ADDR": "true"})
		if err != nil {
			t.Errorf("%s with the override: %v", addr, err)
			continue
		}
		if w := publicAdvertiseWarning(&c); !strings.Contains(w, addr) || !strings.Contains(w, "plain HTTP") {
			t.Errorf("%s with the override: warning %q", addr, w)
		}
	}
}

func mustUUID(t *testing.T) uuid.UUID {
	t.Helper()
	return uuid.NewV7()
}

// endedStream is a Connect stream the server has already ended.
type endedStream struct {
	agentv1.NodeService_ConnectClient
	final error
}

func (s endedStream) Recv() (*agentv1.ConnectResponse, error) { return nil, s.final }

func TestFailedSendReportsTheServersStatus(t *testing.T) {
	removed := status.Error(codes.PermissionDenied, "removed")
	if err := streamStatus(endedStream{final: removed}, io.EOF); status.Code(err) != codes.PermissionDenied || !permanent(err) {
		t.Fatalf("Send EOF: %v", err)
	}
	other := errors.New("broken pipe")
	if err := streamStatus(endedStream{final: removed}, other); !errors.Is(err, other) {
		t.Fatalf("non-EOF send error replaced: %v", err)
	}

	recvErr := make(chan error, 1)
	recvErr <- removed
	if err := endStatus(context.Background(), nil, recvErr, io.EOF); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("endStatus: %v", err)
	}
}

// TestPublishAddress: ports bind to NOOK_AGENT_PUBLISH_ADDR while health
// checks (and the gateway) use the advertise address; both are guarded.
func TestPublishAddress(t *testing.T) {
	base := map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": "192.168.65.254", "NOOK_AGENT_PUBLISH_ADDR": "127.0.0.1"}
	c, err := config.Load[Config](base)
	if err != nil {
		t.Fatal(err)
	}
	publish, err := c.publishAddr()
	if err != nil || publish != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("publishAddr = %v, %v", publish, err)
	}
	m := &instances{advertise: netip.MustParseAddr("192.168.65.254"), publish: publish, nodeID: func() string { return "n1" }}
	spec, err := m.appContainerSpec(&agentv1.StartInstanceCommand{InstanceId: "i1", Port: 8080}, "img", "net")
	if err != nil {
		t.Fatal(err)
	}
	bindings := spec.HostConfig.PortBindings[network.MustParsePort("8080/tcp")]
	if len(bindings) != 1 || bindings[0].HostIP != publish {
		t.Fatalf("bindings = %+v, want only %s", bindings, publish)
	}
	if got := m.healthURL(40000, "/healthz"); got != "http://192.168.65.254:40000/healthz" {
		t.Fatalf("health URL = %s", got)
	}

	// Defaults to the advertise address.
	c, err = config.Load[Config](map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := c.publishAddr(); a != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("default publish address = %s", a)
	}
	for _, bad := range []string{"0.0.0.0", "::", "x", "203.0.113.9"} {
		environ := maps.Clone(base)
		environ["NOOK_AGENT_PUBLISH_ADDR"] = bad
		if _, loadErr := config.Load[Config](environ); loadErr == nil || !strings.Contains(loadErr.Error(), "NOOK_AGENT_PUBLISH_ADDR") {
			t.Errorf("publish %q: %v", bad, loadErr)
		}
	}
	environ := maps.Clone(base)
	environ["NOOK_AGENT_PUBLISH_ADDR"], environ["NOOK_AGENT_ALLOW_PUBLIC_ADVERTISE_ADDR"] = "203.0.113.9", "true"
	c, err = config.Load[Config](environ)
	if err != nil {
		t.Fatal(err)
	}
	if w := publicAdvertiseWarning(&c); !strings.Contains(w, "203.0.113.9") {
		t.Fatalf("warning = %q", w)
	}
}

// TestServerAddressOverride: NOOK_AGENT_SERVER_ADDR replaces the address
// saved at join; without it the saved one is used.
func TestServerAddressOverride(t *testing.T) {
	a := &Agent{}
	a.id.Store(&identity{Server: "127.0.0.1:9443"})
	if got := a.serverAddr(); got != "127.0.0.1:9443" {
		t.Fatalf("saved address: %s", got)
	}
	a.cfg.ServerAddr = "nook-server:9443"
	if got := a.serverAddr(); got != "nook-server:9443" {
		t.Fatalf("override: %s", got)
	}
	for _, bad := range []string{"nook-server", ":9443", "nook-server:"} {
		if _, err := config.Load[Config](map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": "10.0.0.5", "NOOK_AGENT_SERVER_ADDR": bad}); err == nil {
			t.Errorf("server %q accepted", bad)
		}
	}
	if _, err := config.Load[Config](map[string]string{"NOOK_AGENT_ADVERTISE_ADDR": "10.0.0.5", "NOOK_AGENT_SERVER_ADDR": "nook-server:9443"}); err != nil {
		t.Fatal(err)
	}
}
