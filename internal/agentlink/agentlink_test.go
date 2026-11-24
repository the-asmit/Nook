package agentlink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/nodes"
)

func TestToStatusNeverLeaksInternals(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	cases := map[error]codes.Code{
		nodes.ErrNodeRemoved:                     codes.PermissionDenied,
		nodes.ErrCertificateRevoked:              codes.Unauthenticated,
		nodes.ErrUnknownCertificate:              codes.Unauthenticated,
		apperr.Unauthenticated("bad token"):      codes.Unauthenticated,
		apperr.Invalid("x", "bad csr"):           codes.InvalidArgument,
		apperr.Conflict("taken", "name taken"):   codes.AlreadyExists,
		apperr.RateLimited("slow"):               codes.ResourceExhausted,
		errors.New("pq: password for db failed"): codes.Internal,
	}
	for err, want := range cases {
		st := status.Convert(s.toStatus(ctx, err))
		if st.Code() != want {
			t.Errorf("%v: code %s, want %s", err, st.Code(), want)
		}
		if want == codes.Internal && st.Message() != "internal error" {
			t.Errorf("internal detail leaked: %q", st.Message())
		}
	}
}

func TestSessionEndStatus(t *testing.T) {
	for cause, want := range map[error]codes.Code{
		nodes.ErrNodeRemoved: codes.PermissionDenied, errReplaced: codes.Aborted,
		errShuttingDown: codes.Unavailable, context.Canceled: codes.Canceled,
	} {
		if got := status.Code(sessionEndStatus(cause)); got != want {
			t.Errorf("%v: %s, want %s", cause, got, want)
		}
	}
}

func TestConfig(t *testing.T) {
	c := Config{Addr: ":9443", CAPath: "/x/ca.pem", ExtraNames: []string{"localhost", "nook.example.com"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.ResolvePublicAddr("nook.example.com"); got != "nook.example.com:9443" {
		t.Fatalf("public addr %q", got)
	}
	if got := c.CertificateNames("nook.example.com"); !slices.Equal(got, []string{"nook.example.com", "localhost"}) {
		t.Fatalf("names %v", got)
	}
	c.PublicAddr = "agents.example.com:443"
	if got := c.CertificateNames("nook.example.com"); got[0] != "agents.example.com" {
		t.Fatalf("names %v", got)
	}
	for _, bad := range []Config{{Addr: "x", CAPath: "a"}, {Addr: ":1", PublicAddr: "nohost", CAPath: "a"}, {Addr: ":1"}} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestToStatusForAbandonedCalls(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.toStatus(ctx, fmt.Errorf("persist heartbeat: %w", context.Canceled))
	if status.Code(err) != codes.Canceled {
		t.Fatalf("code = %v", status.Code(err))
	}
	// A cancellation the caller did not cause is still an internal error.
	if got := status.Code(s.toStatus(context.Background(), context.Canceled)); got != codes.Internal {
		t.Fatalf("code = %v", got)
	}
}

func TestSessionPrunesAbandonedCommands(t *testing.T) {
	now := time.Now()
	s := &session{inflight: map[string]inflightCommand{
		"old":  {replyTo: "a", expires: now.Add(-time.Millisecond)},
		"live": {replyTo: "b", expires: now.Add(time.Second)},
	}}
	s.prune(now)
	if _, ok := s.inflight["old"]; ok {
		t.Fatal("expired command kept")
	}
	if _, ok := s.inflight["live"]; !ok {
		t.Fatal("live command dropped")
	}
}
