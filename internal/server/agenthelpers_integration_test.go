//go:build integration

package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	dockerclient "github.com/moby/moby/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/the-asmit/nook/internal/agent"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/testinfra"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// adminAlice signs up alice@nook.test as an instance administrator.
func (e *env) adminAlice() user {
	e.t.Helper()
	u := e.newUser("alice@nook.test")
	e.exec("UPDATE users SET is_instance_admin = true WHERE id = $1", u.id)
	return u
}

// joinToken creates a join token through the API.
func (e *env) joinToken(admin user, body map[string]any) (token, caHash string) {
	e.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	r := e.as(admin, http.MethodPost, "/api/v1/join-tokens", body)
	var out struct {
		Token  string `json:"token"`
		CAHash string `json:"ca_hash"`
	}
	r.json(e.t, &out)
	if r.status != http.StatusCreated {
		e.t.Fatalf("create join token: %d %s", r.status, r.body)
	}
	return out.Token, out.CAHash
}

var quietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// joinAgent runs `nook-agent join` against the instance and returns the
// agent's state directory.
func joinAgent(t *testing.T, grpcAddr, token, caHash, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "agent")
	_, err := agent.Join(context.Background(), &agent.JoinOptions{
		Server: grpcAddr, Token: token, CAHash: caHash, Name: name, StateDir: dir,
		Labels: map[string]string{"zone": "test"},
	}, quietLogger)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	return dir
}

// runningAgent is an agent running `nook-agent run` in the test process,
// against the machine's real Docker engine.
type runningAgent struct {
	*agent.Agent
	stop context.CancelFunc
	done chan struct{}
	err  error
}

// exited waits up to within for Run to return and reports its error.
func (ra *runningAgent) exited(within time.Duration) (bool, error) {
	select {
	case <-ra.done:
		return true, ra.err
	case <-time.After(within):
		return false, nil
	}
}

// agentConfig is the configuration of a test agent: fast reconnects, and
// build containers on the test network, where the registry is.
func agentConfig(t *testing.T, stateDir string) agent.Config {
	t.Helper()
	return agentConfigWith(t, stateDir, nil)
}

// agentConfigWith is agentConfig with overrides. Every test agent installs
// the egress firewall under chains of its own, removed when the test ends.
// Builds run on a filtered build network of this package (shared.buildNetwork), as in production, and
// reach the registry by its address on the shared network (allowed).
func agentConfigWith(t *testing.T, stateDir string, overrides map[string]string) agent.Config {
	t.Helper()
	environ := map[string]string{
		"NOOK_AGENT_STATE_DIR": stateDir, "NOOK_AGENT_HEALTH_ADDR": "127.0.0.1:0",
		"NOOK_AGENT_RECONNECT_MIN": "50ms", "NOOK_AGENT_RECONNECT_MAX": "500ms",
		"NOOK_AGENT_RENEW_CHECK_INTERVAL": "1h",
		"NOOK_AGENT_BUILD_HOSTS":          testinfra.RegistryAlias + "=" + registryIP(t),
		"NOOK_AGENT_BUILD_EGRESS_ALLOW":   registryIP(t),
		"NOOK_AGENT_ADVERTISE_ADDR":       "127.0.0.1", "NOOK_AGENT_REGISTRY_PULL_ADDR": shared.storage.Registry.Addr,
		"NOOK_AGENT_FIREWALL_CHAIN": testChain(), "NOOK_AGENT_BUILD_NETWORK": shared.buildNetwork,
	}
	maps.Copy(environ, overrides)
	cfg, err := config.Load[agent.Config](environ)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// testChain is a unique iptables chain prefix for one test agent.
func testChain() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return "NT" + strings.ToUpper(hex.EncodeToString(b))
}

func runAgent(t *testing.T, stateDir string) *runningAgent {
	t.Helper()
	return runAgentWith(t, stateDir, quietLogger)
}

func runAgentWith(t *testing.T, stateDir string, logger *slog.Logger) *runningAgent {
	t.Helper()
	cfg := agentConfig(t, stateDir)
	return runConfiguredAgent(t, &cfg, logger)
}

// runConfiguredAgent runs an agent with cfg until the test ends, then
// removes its firewall chains.
func runConfiguredAgent(t *testing.T, cfg *agent.Config, logger *slog.Logger) *runningAgent {
	t.Helper()
	a, err := agent.New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ra := &runningAgent{Agent: a, stop: cancel, done: make(chan struct{})}
	go func() {
		ra.err = a.Run(ctx)
		close(ra.done)
	}()
	t.Cleanup(func() {
		cancel()
		if ok, _ := ra.exited(10 * time.Second); !ok {
			t.Error("agent did not stop")
		}
		_ = a.Close()
		ctx, cancelRemove := context.WithTimeout(context.Background(), time.Minute)
		defer cancelRemove()
		removeNodeContainers(t, ctx, a.NodeID())
		if err := agent.RemoveFirewall(ctx, cfg, quietLogger); err != nil {
			t.Errorf("remove the test agent's firewall: %v", err)
		}
	})
	return ra
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", within, what)
		}
		timer := time.NewTimer(20 * time.Millisecond)
		<-timer.C
	}
}

// nodeStatus reads a node's status through the API.
func (e *env) nodeStatus(admin user, name string) string {
	e.t.Helper()
	r := e.as(admin, http.MethodGet, "/api/v1/nodes/"+name, nil)
	if r.status != http.StatusOK {
		return "http " + http.StatusText(r.status)
	}
	var n struct {
		Status string `json:"status"`
	}
	r.json(e.t, &n)
	return n.Status
}

// sharedCA loads the package's CA (tests may mint certificates with it).
func sharedCA(t *testing.T) *pki.CA {
	t.Helper()
	ca, _, err := pki.LoadOrCreateCA(shared.caPath)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// agentIdentity reads the certificate and key `nook-agent join` stored.
func agentIdentity(t *testing.T, stateDir string) tls.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, "node.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := pki.ParseKeyPair(data)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

// rawClient dials the gRPC endpoint presenting cert (none if nil).
func rawClient(t *testing.T, addr string, cert *tls.Certificate) agentv1.NodeServiceClient {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(sharedCA(t).Certificate())
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentv1.NewNodeServiceClient(conn)
}

// openSession starts a Connect stream and returns it after the first
// response (or the error that ended it).
func openSession(t *testing.T, c agentv1.NodeServiceClient) (agentv1.NodeService_ConnectClient, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return openSessionCtx(ctx, t, c)
}

// openSessionCtx is openSession on a stream that ends with ctx.
func openSessionCtx(ctx context.Context, t *testing.T, c agentv1.NodeServiceClient) (agentv1.NodeService_ConnectClient, error) {
	t.Helper()
	stream, err := c.Connect(ctx)
	if err != nil {
		return nil, err
	}
	hello := &agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_Hello{Hello: &agentv1.Hello{
		Info: &agentv1.NodeInfo{Hostname: "fake", AgentVersion: "test"},
	}}}
	if sendErr := stream.Send(hello); sendErr != nil {
		return nil, sendErr
	}
	first, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	if first.GetAccepted() == nil {
		t.Fatalf("first message %v", first)
	}
	return stream, nil
}

// removeNodeContainers removes the app containers a test agent left
// running (apps outlive their agent by design) and their networks.
func removeNodeContainers(t *testing.T, ctx context.Context, nodeID string) {
	t.Helper()
	d, err := dockerclient.New(dockerclient.FromEnv)
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = d.Close() }()
	list, err := d.ContainerList(ctx, dockerclient.ContainerListOptions{All: true, Filters: dockerclient.Filters{}.Add("label", "nook.node="+nodeID)})
	if err != nil {
		t.Error(err)
		return
	}
	apps := map[string]bool{}
	for i := range list.Items {
		apps[list.Items[i].Labels["nook.app"]] = true
		if _, err := d.ContainerRemove(ctx, list.Items[i].ID, dockerclient.ContainerRemoveOptions{Force: true}); err != nil {
			t.Errorf("remove container: %v", err)
		}
	}
	for app := range apps {
		if app != "" {
			_, _ = d.NetworkRemove(ctx, "nook-app-"+app, dockerclient.NetworkRemoveOptions{})
		}
	}
}

var sharedRegistryIP struct {
	once sync.Once
	ip   string
	err  error
}

// registryIP is the shared registry's address on the shared network.
func registryIP(t *testing.T) string {
	t.Helper()
	sharedRegistryIP.once.Do(func() {
		sharedRegistryIP.ip, sharedRegistryIP.err = shared.storage.Registry.ContainerIP(context.Background())
	})
	if sharedRegistryIP.err != nil {
		t.Fatal(sharedRegistryIP.err)
	}
	return sharedRegistryIP.ip
}
