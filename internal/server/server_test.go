package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// closedPort returns a localhost address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestNewFailsWhenDependenciesAreUnreachable(t *testing.T) {
	env := devEnviron()
	env["NOOK_POSTGRES_URL"] = "postgres://nook:pw@" + closedPort(t) + "/nook?sslmode=disable"
	env["NOOK_STARTUP_TIMEOUT"] = "1s"
	env["NOOK_HTTP_ADDR"] = "127.0.0.1:0"
	cfg, err := config.Load[Config](env)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = New(context.Background(), &cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "wait for postgres") {
		t.Fatalf("New() = %v, want a postgres startup error", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("New() took %s; the startup timeout was not applied", elapsed)
	}
}
