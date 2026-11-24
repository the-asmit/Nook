//go:build integration

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/logging"
	"github.com/the-asmit/nook/internal/server/api"
	"github.com/the-asmit/nook/internal/testinfra"
)

func readyz(t *testing.T, base string) (int, api.ReadinessResponse) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+api.RouteReadyz, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body api.ReadinessResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /readyz: %v", err)
	}
	return resp.StatusCode, body
}

// eventuallyReadyz polls /readyz until it returns want, with a deadline.
func eventuallyReadyz(t *testing.T, base string, want int) api.ReadinessResponse {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		code, body := readyz(t, base)
		if code == want {
			return body
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz = %d %+v, want %d", code, body, want)
		}
	}
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestServerLifecycleAndReadiness(t *testing.T) {
	pg, pgURL := testinfra.PostgresT(t)
	rd, redisURL := testinfra.RedisT(t)

	environ := baseEnviron(pgURL)
	environ["NOOK_HTTP_ADDR"] = "127.0.0.1:0"
	environ["NOOK_REDIS_URL"] = redisURL
	environ["NOOK_READINESS_TIMEOUT"] = "500ms"
	cfg, err := config.Load[Config](environ)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger, err := logging.New(logs, logging.Config{Level: "debug"})
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(context.Background(), &cfg, logger)
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	base := "http://" + srv.Addr().String()

	t.Run("ready when dependencies are up", func(t *testing.T) {
		code, body := readyz(t, base)
		if code != http.StatusOK || body.Checks["postgres"] != "ok" || body.Checks["redis"] != "ok" {
			t.Fatalf("/readyz = %d %+v", code, body)
		}
	})

	t.Run("migrations ran on startup", func(t *testing.T) {
		if !strings.Contains(logs.String(), "database schema is up to date") {
			t.Fatal("no migration log line")
		}
	})

	t.Run("metrics include http and pool metrics", func(t *testing.T) {
		out := getBody(t, base+api.RouteMetrics)
		for _, want := range []string{
			`nook_http_requests_total{method="GET",route="/readyz",status="200"}`,
			"nook_postgres_pool_max_conns 10",
			`nook_build_info{`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("metrics missing %q", want)
			}
		}
	})

	t.Run("not ready while postgres hangs, ready again after", func(t *testing.T) {
		unpause := testinfra.Pause(t, pg)
		body := eventuallyReadyz(t, base, http.StatusServiceUnavailable)
		if !slices.Equal(body.Failing, []string{"postgres"}) || body.Checks["redis"] != "ok" {
			t.Fatalf("body = %+v, want only postgres failing", body)
		}
		unpause()
		eventuallyReadyz(t, base, http.StatusOK)
	})

	t.Run("not ready when redis is stopped", func(t *testing.T) {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		if err := rd.Stop(stopCtx, nil); err != nil {
			t.Fatal(err)
		}
		body := eventuallyReadyz(t, base, http.StatusServiceUnavailable)
		if !slices.Equal(body.Failing, []string{"redis"}) || body.Checks["postgres"] != "ok" {
			t.Fatalf("body = %+v, want only redis failing", body)
		}
	})

	t.Run("graceful shutdown", func(t *testing.T) {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Serve() = %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("Serve() did not return after the context was canceled")
		}
		if !strings.Contains(logs.String(), "http server stopped") {
			t.Fatal("no shutdown log line")
		}
	})
}
