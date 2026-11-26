//go:build integration

package gateway

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/testcontainers/testcontainers-go"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/redis"
	"github.com/the-asmit/nook/internal/routes"
	"github.com/the-asmit/nook/internal/testinfra"
)

var redisURL string

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	c, url, err := testinfra.StartRedis(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(c) }()
	redisURL = url
	return m.Run()
}

func redisConfig(t *testing.T) redis.Config {
	t.Helper()
	return redis.Config{
		URL: config.NewSecret(redisURL), DialTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, PoolSize: 10,
	}
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRouteEventsAndResync(t *testing.T) {
	f := newFixture(t, nil)
	rcfg := redisConfig(t)
	rdb, err := redis.NewClient(&rcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go f.table.run(ctx, rdb, 500*time.Millisecond)

	// An app appears and is announced: routed long before the resync.
	app := routes.Route{AppID: uuid.NewV7(), Host: "live--ws.apps.localhost", Access: routes.AccessPublic, State: routes.StateStarting}
	f.cp.set(&app)
	pub := routes.NewPublisher(rdb)
	publishUntil(t, pub, app.AppID, func() bool { _, ok := f.table.lookup(app.Host); return ok })

	// It goes live on another port: the event updates the upstream.
	app.State, app.Upstream = routes.StateRunning, "10.1.2.3:4567"
	f.cp.set(&app)
	publishUntil(t, pub, app.AppID, func() bool { r, _ := f.table.lookup(app.Host); return r.Upstream == "10.1.2.3:4567" })

	// A change without an event (a missed message) heals at the resync.
	app.Upstream = "10.1.2.3:9999"
	f.cp.set(&app)
	eventually(t, 5*time.Second, "the resync", func() bool { r, _ := f.table.lookup(app.Host); return r.Upstream == "10.1.2.3:9999" })

	// Deleted and announced: gone.
	f.cp.remove(app.AppID)
	publishUntil(t, pub, app.AppID, func() bool { _, ok := f.table.lookup(app.Host); return !ok })
}

// publishUntil publishes the app's change until cond holds: the
// subscription may not be active yet when the first message goes out.
func publishUntil(t *testing.T, pub *routes.Publisher, id uuid.UUID, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("route event not applied")
		}
		pub.Changed(t.Context(), id)
		time.Sleep(50 * time.Millisecond)
	}
}

// startGateway runs a full gateway against the fake control plane.
func startGateway(t *testing.T, cp *fakeCP, adjust func(*Config)) (*Gateway, func() error) {
	t.Helper()
	cfg := testConfig(cp.srv.URL)
	cfg.Redis = redisConfig(t)
	cfg.ResyncInterval = 200 * time.Millisecond
	if adjust != nil {
		adjust(cfg)
	}
	g, err := New(t.Context(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx) }()
	stop := func() error {
		cancel()
		err := <-done
		g.Close()
		return err
	}
	t.Cleanup(func() {
		select {
		case <-ctx.Done():
		default:
			_ = stop()
		}
	})
	return g, stop
}

func TestGatewayServesAndDrainsWebSockets(t *testing.T) {
	cp := newFakeCP(t)
	up := newUpgradeEcho(t)
	app := routes.Route{AppID: uuid.NewV7(), Host: "ws--ws.apps.localhost", Access: routes.AccessPublic, State: routes.StateRunning, Upstream: hostOf(up)}
	cp.set(&app)
	g, stop := startGateway(t, cp, func(c *Config) { c.DrainTimeout = 10 * time.Second })
	addr := g.Addrs()[0].String()

	// Ops endpoints.
	for _, p := range []string{"/healthz", "/readyz", "/metrics"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+g.OpsAddr().String()+p, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}

	conn := dialUpgrade(t, addr, app.Host)
	echo(t, conn, "before shutdown")

	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	// New connections are refused once draining starts...
	eventually(t, 5*time.Second, "the listener to close", func() bool {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", addr)
		if err != nil {
			return true
		}
		_ = c.Close()
		return false
	})
	// ...while the open WebSocket keeps working until its owner closes it.
	echo(t, conn, "during the drain")
	select {
	case err := <-stopped:
		t.Fatalf("Serve returned (%v) with a WebSocket still open", err)
	default:
	}
	_ = conn.Close()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the drain did not finish after the WebSocket closed")
	}
}

func TestDrainDeadlineClosesWebSockets(t *testing.T) {
	cp := newFakeCP(t)
	up := newUpgradeEcho(t)
	app := routes.Route{AppID: uuid.NewV7(), Host: "ws--ws.apps.localhost", Access: routes.AccessPublic, State: routes.StateRunning, Upstream: hostOf(up)}
	cp.set(&app)
	g, stop := startGateway(t, cp, func(c *Config) { c.DrainTimeout = time.Second })
	conn := dialUpgrade(t, g.Addrs()[0].String(), app.Host)
	defer func() { _ = conn.Close() }()
	echo(t, conn, "hello")
	start := time.Now()
	if err := stop(); err != nil {
		t.Fatalf("Serve = %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("drain took %v with a 1s deadline", d)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the WebSocket is still open after the drain deadline")
	}
}

func TestGatewayWaitsForTheControlPlane(t *testing.T) {
	cp := newFakeCP(t)
	cp.mu.Lock()
	cp.failNext = true // the first load fails; the gateway retries
	cp.mu.Unlock()
	g, _ := startGateway(t, cp, nil)
	if !g.table.loaded.Load() {
		t.Fatal("New returned before the routes were loaded")
	}
}
