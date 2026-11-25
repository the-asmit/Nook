//go:build integration

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/the-asmit/nook/internal/agent"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/testinfra"
)

// TestAgentJoinsConnectsAndIsInspected runs the real agent against the
// real Docker daemon that testcontainers uses.
func TestAgentJoinsConnectsAndIsInspected(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	if caHash != sharedCA(t).Fingerprint() {
		t.Fatalf("API advertised CA %s", caHash)
	}
	state := joinAgent(t, e.primary.grpc, token, caHash, "worker-1")
	if s := e.nodeStatus(alice, "worker-1"); s != "joining" {
		t.Fatalf("after join: %s", s)
	}
	a := runAgent(t, state)
	eventually(t, 15*time.Second, "node ready", func() bool { return e.nodeStatus(alice, "worker-1") == "ready" })
	if !a.Connected() {
		t.Fatal("agent not connected")
	}

	// A container Nook manages, identified by its label.
	ctr, err := testcontainers.Run(context.Background(), testinfra.RedisImage,
		testcontainers.WithLabels(map[string]string{agent.ManagedLabel: "true", "nook.app": "demo"}))
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatal(err)
	}

	var detail struct {
		CPUCount         int32             `json:"cpu_count"`
		MemoryTotalBytes int64             `json:"memory_total_bytes"`
		DockerVersion    string            `json:"docker_version"`
		Labels           map[string]string `json:"labels"`
		Heartbeat        *struct {
			MemoryAvailableBytes int64 `json:"memory_available_bytes"`
			DockerReachable      bool  `json:"docker_reachable"`
		} `json:"heartbeat"`
		Events []struct{ To string } `json:"events"`
	}
	e.as(alice, http.MethodGet, "/api/v1/nodes/worker-1", nil).json(t, &detail)
	if detail.CPUCount <= 0 || detail.MemoryTotalBytes <= 0 || detail.DockerVersion == "" || detail.Labels["zone"] != "test" {
		t.Fatalf("node detail %+v", detail)
	}
	if detail.Heartbeat == nil || detail.Heartbeat.MemoryAvailableBytes <= 0 || !detail.Heartbeat.DockerReachable {
		t.Fatalf("heartbeat %+v", detail.Heartbeat)
	}

	r := e.as(alice, http.MethodPost, "/api/v1/nodes/worker-1/inspect", nil)
	var inspect struct {
		Docker struct {
			ServerVersion string `json:"server_version"`
			CPUs          int32  `json:"cpus"`
		} `json:"docker"`
		Containers []struct {
			ID     string            `json:"id"`
			Labels map[string]string `json:"labels"`
		} `json:"containers"`
	}
	r.json(t, &inspect)
	if r.status != http.StatusOK || inspect.Docker.ServerVersion == "" || inspect.Docker.CPUs <= 0 {
		t.Fatalf("inspect: %d %s", r.status, r.body)
	}
	if !slices.ContainsFunc(inspect.Containers, func(c struct {
		ID     string            `json:"id"`
		Labels map[string]string `json:"labels"`
	}) bool {
		return c.ID == ctr.GetContainerID() && c.Labels["nook.app"] == "demo"
	}) {
		t.Fatalf("managed container missing from %+v", inspect.Containers)
	}

	actions := e.auditActions()
	for _, want := range []string{"join_token.create", "node.join"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}

func TestJoinTokenRules(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	join := func(token, caHash, name string) error {
		_, err := agent.Join(context.Background(), &agent.JoinOptions{
			Server: e.primary.grpc, Token: token, CAHash: caHash, Name: name, StateDir: filepath.Join(t.TempDir(), name),
		}, quietLogger)
		return err
	}
	rejected := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "invalid, expired, revoked or already used")
	}

	token, caHash := e.joinToken(alice, nil)
	if err := join(token, caHash, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := join(token, caHash, "a2"); !rejected(err) {
		t.Fatalf("reused token: %v", err)
	}

	expired, _ := e.joinToken(alice, nil)
	e.exec("UPDATE join_tokens SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE uses = 0")
	if err := join(expired, caHash, "a3"); !rejected(err) {
		t.Fatalf("expired token: %v", err)
	}

	revoked, _ := e.joinToken(alice, nil)
	var id string
	if err := e.db.QueryRow(context.Background(), "SELECT id::text FROM join_tokens WHERE revoked_at IS NULL AND expires_at > now() AND uses = 0").Scan(&id); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, e.as(alice, http.MethodDelete, "/api/v1/join-tokens/"+id, nil), 204, "revoke")
	if err := join(revoked, caHash, "a4"); !rejected(err) {
		t.Fatalf("revoked token: %v", err)
	}

	multi, _ := e.joinToken(alice, map[string]any{"max_uses": 2})
	if join(multi, caHash, "m1") != nil || join(multi, caHash, "m2") != nil {
		t.Fatal("multi-use token rejected early")
	}
	if err := join(multi, caHash, "m3"); !rejected(err) {
		t.Fatalf("third use: %v", err)
	}

	again, _ := e.joinToken(alice, nil)
	if err := join(again, caHash, "a1"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate name: %v", err)
	}
	if n := e.count("SELECT uses FROM join_tokens WHERE uses = 0 AND revoked_at IS NULL AND expires_at > now()"); n != 0 {
		t.Fatal("a failed join consumed its token")
	}
}

func TestCAPinningRefusesBeforeSendingToken(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	other, _, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "other.pem"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = agent.Join(context.Background(), &agent.JoinOptions{
		Server: e.primary.grpc, Token: token, CAHash: other.Fingerprint(), StateDir: filepath.Join(t.TempDir(), "x"), Name: "pin",
	}, quietLogger)
	if err == nil || !strings.Contains(err.Error(), "does not match --ca-hash; the token was not sent") {
		t.Fatalf("join with the wrong CA hash: %v", err)
	}
	if strings.Contains(e.logs.String(), "/nook.agent.v1.NodeService/Join") {
		t.Fatal("the server received a Join call although the pin did not match")
	}
	if n := e.count("SELECT uses FROM join_tokens"); n != 0 {
		t.Fatal("token was used")
	}
	// The same token still works with the right pin.
	joinAgent(t, e.primary.grpc, token, caHash, "pin")
}

// mintCert signs a client certificate for an existing node with custom
// validity, using the CA key directly (as only an attacker holding it, or
// a test, could).
func mintCert(t *testing.T, caPath string, template *x509.Certificate) tls.Certificate {
	t.Helper()
	data, err := pki.ReadPrivateFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	caCert, caKey, err := pki.ParseKeyPair(data)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestConnectionAuthentication(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	state := joinAgent(t, e.primary.grpc, token, caHash, "auth-node")
	good := agentIdentity(t, state)

	t.Run("valid certificate", func(t *testing.T) {
		if _, err := openSession(t, rawClient(t, e.primary.grpc, &good)); err != nil {
			t.Fatalf("valid certificate rejected: %v", err)
		}
	})
	t.Run("no client certificate", func(t *testing.T) {
		_, err := openSession(t, rawClient(t, e.primary.grpc, nil))
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("certificate from another CA", func(t *testing.T) {
		otherPath := filepath.Join(t.TempDir(), "other.pem")
		if _, _, err := pki.LoadOrCreateCA(otherPath); err != nil {
			t.Fatal(err)
		}
		forged := mintCert(t, otherPath, &x509.Certificate{
			SerialNumber: good.Leaf.SerialNumber, Subject: good.Leaf.Subject, URIs: good.Leaf.URIs,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if _, err := openSession(t, rawClient(t, e.primary.grpc, &forged)); err == nil {
			t.Fatal("certificate from a foreign CA accepted")
		}
	})
	t.Run("expired certificate", func(t *testing.T) {
		expired := mintCert(t, shared.caPath, &x509.Certificate{
			SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "x"}, URIs: good.Leaf.URIs,
			NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if _, err := openSession(t, rawClient(t, e.primary.grpc, &expired)); err == nil {
			t.Fatal("expired certificate accepted")
		}
	})
	t.Run("certificate never issued", func(t *testing.T) {
		unknown := mintCert(t, shared.caPath, &x509.Certificate{
			SerialNumber: big.NewInt(777), Subject: pkix.Name{CommonName: "x"}, URIs: good.Leaf.URIs,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		_, err := openSession(t, rawClient(t, e.primary.grpc, &unknown))
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("removed node", func(t *testing.T) {
		expectStatus(t, e.as(alice, http.MethodDelete, "/api/v1/nodes/auth-node", nil), 204, "remove")
		_, err := openSession(t, rawClient(t, e.primary.grpc, &good))
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), "removed") {
			t.Fatalf("err = %v", err)
		}
		if n := e.count("SELECT count(*) FROM node_certificates WHERE revoked_at IS NULL"); n != 0 {
			t.Fatal("removal left certificates unrevoked")
		}
	})
}

func TestCertificateRenewal(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	state := joinAgent(t, e.primary.grpc, token, caHash, "renew-node")
	old := agentIdentity(t, state)

	cfg := agentConfig(t, state)
	a, err := agent.New(&cfg, quietLogger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err = a.Renew(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	renewed := agentIdentity(t, state)
	if renewed.Leaf.SerialNumber.Cmp(old.Leaf.SerialNumber) == 0 || pki.SamePublicKey(renewed.Leaf.PublicKey, old.Leaf.PublicKey) {
		t.Fatal("renewal must issue a new certificate for a new key")
	}
	if _, err = openSession(t, rawClient(t, e.primary.grpc, &renewed)); err != nil {
		t.Fatalf("renewed certificate rejected: %v", err)
	}
	_, err = openSession(t, rawClient(t, e.primary.grpc, &old))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("old certificate after renewal: %v", err)
	}
	if !slices.Contains(e.auditActions(), "node.certificate_renew") {
		t.Fatal("renewal not audited")
	}
}

func TestRemovedNodeIsCutOff(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	token, caHash := e.joinToken(alice, nil)
	state := joinAgent(t, e.primary.grpc, token, caHash, "doomed")
	a := runAgent(t, state)
	eventually(t, 15*time.Second, "agent connected", a.Connected)

	expectStatus(t, e.as(alice, http.MethodDelete, "/api/v1/nodes/doomed", nil), 204, "remove")
	ok, err := a.exited(10 * time.Second)
	if !ok {
		t.Fatal("removed node's agent kept running")
	}
	if err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("agent exited with %v", err)
	}
	if s := e.nodeStatus(alice, "doomed"); s != "http Not Found" {
		t.Fatalf("removed node still listed: %s", s)
	}
	expectStatus(t, e.as(alice, http.MethodDelete, "/api/v1/nodes/doomed", nil), 404, "remove again")
}
