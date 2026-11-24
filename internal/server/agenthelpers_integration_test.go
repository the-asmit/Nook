//go:build integration

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/the-asmit/nook/internal/agent"
	"github.com/the-asmit/nook/internal/pki"
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

func runAgent(t *testing.T, stateDir string) *runningAgent {
	t.Helper()
	cfg := agent.Config{StateDir: stateDir, HealthAddr: "127.0.0.1:0", ReconnectMin: 50 * time.Millisecond,
		ReconnectMax: 500 * time.Millisecond, RenewCheckInterval: time.Hour}
	cfg.Log.Level = "info"
	a, err := agent.New(&cfg, quietLogger)
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
