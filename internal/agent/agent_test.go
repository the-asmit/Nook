package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/the-asmit/nook/internal/pki"
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
	c := Config{StateDir: "/var/lib/nook-agent", HealthAddr: "127.0.0.1:9101", ReconnectMin: time.Second, ReconnectMax: time.Minute, RenewCheckInterval: time.Minute}
	c.Log.Level = "info"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.ReconnectMax = time.Millisecond
	if err := c.Validate(); err == nil {
		t.Fatal("max below min accepted")
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
