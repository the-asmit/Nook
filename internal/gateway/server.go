package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/activity"
	platformmetrics "github.com/the-asmit/nook/internal/platform/metrics"
	"github.com/the-asmit/nook/internal/platform/redis"
	"github.com/the-asmit/nook/internal/version"
)

// ServiceName names the gateway in logs and metrics.
const ServiceName = "nook-gateway"

// startupTimeout bounds the first route table load.
const startupTimeout = 30 * time.Second

// Gateway is a running nook-gateway.
type Gateway struct {
	cfg      Config
	logger   *slog.Logger
	redis    *goredis.Client
	table    *table
	handler  *handler
	conns    *connTracker
	reg      *prometheus.Registry
	activity *activity.Recorder

	servers   []*http.Server
	listeners []net.Listener
	ops       *http.Server
	opsLn     net.Listener
}

// New connects to Redis, loads the route table and binds the listeners.
func New(ctx context.Context, cfg *Config, logger *slog.Logger) (*Gateway, error) {
	reg, err := platformmetrics.NewRegistry(ServiceName, version.Get())
	if err != nil {
		return nil, err
	}
	m, err := newMetrics(reg)
	if err != nil {
		return nil, err
	}
	rdb, err := redis.NewClient(&cfg.Redis)
	if err != nil {
		return nil, err
	}
	g := &Gateway{cfg: *cfg, logger: logger, redis: rdb, conns: newConnTracker(), reg: reg}
	cp := newControlPlane(cfg.ControlPlaneURL, cfg.Secret.Reveal())
	g.table = newTable(cp, logger, m)
	//nolint:contextcheck // the proxies run on each request's own context.
	if g.handler, err = newHandler(&g.cfg, g.table, cp, m, g.conns, logger); err != nil {
		g.Close()
		return nil, err
	}
	g.activity = activity.NewRecorder(rdb, logger)
	g.handler.touch = g.activity.Touch
	loadCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	if err := g.waitForRoutes(loadCtx); err != nil {
		g.Close()
		return nil, err
	}
	if err := g.listen(ctx, cp); err != nil {
		g.Close()
		return nil, err
	}
	return g, nil
}

// waitForRoutes loads the table, retrying until ctx ends: serving with an
// empty table would answer 404 for every app.
func (g *Gateway) waitForRoutes(ctx context.Context) error {
	for {
		err := g.table.resync(ctx)
		if err == nil {
			g.logger.InfoContext(ctx, "route table loaded", "routes", g.table.size())
			return nil
		}
		g.logger.WarnContext(ctx, "control plane not reachable yet; retrying", "error", err.Error())
		select {
		case <-ctx.Done():
			return fmt.Errorf("load routes: %w", err)
		case <-time.After(time.Second):
		}
	}
}

func (g *Gateway) server(handler http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: responses may stream (SSE, downloads).
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       slog.NewLogLogger(g.logger.Handler(), slog.LevelDebug),
	}
}

func (g *Gateway) bind(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	g.listeners = append(g.listeners, ln)
	return ln, nil
}

// listen binds the public listeners for the TLS mode and the ops listener.
func (g *Gateway) listen(ctx context.Context, cp *controlPlane) error {
	switch g.cfg.TLSMode {
	case TLSOff, TLSProxy:
		if _, err := g.bind(ctx, g.cfg.HTTPAddr); err != nil {
			return err
		}
		g.servers = append(g.servers, g.server(g.handler, nil))
	default:
		tlsCfg, httpHandler, err := g.tls(cp)
		if err != nil {
			return err
		}
		if _, err := g.bind(ctx, g.cfg.HTTPAddr); err != nil {
			return err
		}
		g.servers = append(g.servers, g.server(httpHandler, nil))
		ln, bindErr := g.bind(ctx, g.cfg.HTTPSAddr)
		if bindErr != nil {
			return bindErr
		}
		g.listeners[len(g.listeners)-1] = tls.NewListener(ln, tlsCfg)
		g.servers = append(g.servers, g.server(g.handler, tlsCfg))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !g.table.loaded.Load() {
			http.Error(w, "routes not loaded", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("GET /metrics", platformmetrics.Handler(g.reg))
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", g.cfg.OpsAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", g.cfg.OpsAddr, err)
	}
	g.opsLn = ln
	g.ops = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return nil
}

// Addrs returns the public listeners' addresses (HTTP first).
func (g *Gateway) Addrs() []net.Addr {
	out := make([]net.Addr, 0, len(g.listeners))
	for _, ln := range g.listeners {
		out = append(out, ln.Addr())
	}
	return out
}

// OpsAddr returns the ops listener's address.
func (g *Gateway) OpsAddr() net.Addr { return g.opsLn.Addr() }

// Serve runs the gateway until ctx ends, then drains: listeners close,
// requests in flight and upgraded connections (WebSockets) may finish
// within the drain timeout, and whatever remains is closed.
func (g *Gateway) Serve(ctx context.Context) error {
	tableCtx, stopTable := context.WithCancel(context.WithoutCancel(ctx))
	defer stopTable()
	go g.table.run(tableCtx, g.redis, g.cfg.ResyncInterval)
	activityDone := make(chan struct{})
	go func() {
		defer close(activityDone)
		g.activity.Run(tableCtx, g.cfg.ActivityFlush)
	}()
	defer func() {
		stopTable()
		<-activityDone // the final flush, before the Redis client closes
	}()
	errs := make(chan error, len(g.servers)+1)
	for i, srv := range g.servers {
		go func() { errs <- srv.Serve(g.listeners[i]) }()
	}
	go func() { errs <- g.ops.Serve(g.opsLn) }()
	g.logger.InfoContext(ctx, "nook-gateway is serving", "mode", g.cfg.TLSMode, "addrs", fmt.Sprint(g.Addrs()), "ops", g.opsLn.Addr().String())

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	g.drain(ctx)
	return runErr
}

// drain runs after ctx ended, on a context of its own with the drain
// timeout.
func (g *Gateway) drain(ctx context.Context) {
	g.logger.Info("draining connections", "timeout", g.cfg.DrainTimeout.String())
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), g.cfg.DrainTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range g.servers {
		wg.Go(func() {
			if err := srv.Shutdown(ctx); err != nil {
				_ = srv.Close()
			}
		})
	}
	wg.Wait()
	// http.Server.Shutdown does not wait for hijacked connections.
	if n := g.conns.wait(ctx); n > 0 {
		g.logger.Warn("closed upgraded connections at the drain deadline", "connections", n)
	}
	shutdownCtx, cancelOps := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelOps()
	_ = g.ops.Shutdown(shutdownCtx)
	g.logger.Info("drained")
}

// Close releases the Redis client and listeners not yet served.
func (g *Gateway) Close() {
	if g.redis != nil {
		_ = g.redis.Close()
	}
}

// connTracker follows hijacked connections so the drain can wait for them.
type connTracker struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
	empty chan struct{}
}

func newConnTracker() *connTracker {
	return &connTracker{conns: map[*trackedConn]struct{}{}}
}

type trackedConn struct {
	net.Conn
	t    *connTracker
	m    *metrics
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.t.mu.Lock()
		delete(c.t.conns, c)
		if len(c.t.conns) == 0 && c.t.empty != nil {
			close(c.t.empty)
			c.t.empty = nil
		}
		c.t.mu.Unlock()
		c.m.upgraded.Dec()
	})
	return c.Conn.Close()
}

func (t *connTracker) track(conn net.Conn, m *metrics) net.Conn {
	tc := &trackedConn{Conn: conn, t: t, m: m}
	t.mu.Lock()
	t.conns[tc] = struct{}{}
	t.mu.Unlock()
	m.upgraded.Inc()
	return tc
}

// wait blocks until every tracked connection closed or ctx ends, then
// closes the rest and returns how many it closed.
func (t *connTracker) wait(ctx context.Context) int {
	t.mu.Lock()
	if len(t.conns) == 0 {
		t.mu.Unlock()
		return 0
	}
	if t.empty == nil {
		t.empty = make(chan struct{})
	}
	empty := t.empty
	t.mu.Unlock()
	select {
	case <-empty:
		return 0
	case <-ctx.Done():
	}
	t.mu.Lock()
	rest := make([]*trackedConn, 0, len(t.conns))
	for c := range t.conns {
		rest = append(rest, c)
	}
	t.mu.Unlock()
	for _, c := range rest {
		_ = c.Close()
	}
	return len(rest)
}
