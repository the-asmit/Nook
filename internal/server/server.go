package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/agentlink"
	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/builds"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/leader"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/health"
	"github.com/the-asmit/nook/internal/platform/httpserver"
	"github.com/the-asmit/nook/internal/platform/metrics"
	"github.com/the-asmit/nook/internal/platform/postgres"
	"github.com/the-asmit/nook/internal/platform/redis"
	"github.com/the-asmit/nook/internal/rollout"
	"github.com/the-asmit/nook/internal/routes"
	"github.com/the-asmit/nook/internal/server/api"
	"github.com/the-asmit/nook/internal/version"
	"github.com/the-asmit/nook/internal/visitor"
	"github.com/the-asmit/nook/migrations"
)

// ServiceName identifies the control plane in logs, metrics and
// pg_stat_activity.
const ServiceName = "nook-server"

// Server is a started control plane: dependencies connected, schema
// migrated and the HTTP listener bound.
type Server struct {
	logger   *slog.Logger
	pool     *pgxpool.Pool
	redis    *goredis.Client
	provider *identity.Provider
	http     *httpserver.Server

	// Worker-node link (stage 3).
	instance string
	ca       *pki.CA
	hub      *agentlink.Hub
	grpc     *agentlink.Server
	elector  *leader.Elector
	detector *nodes.Detector

	// Builds (stage 4).
	objects    *objstore.Client
	apps       *apps.Service
	logs       *builds.Logs
	dispatcher *builds.Dispatcher
	janitor    *builds.Janitor
	gcWindow   *builds.GCWindow
	rollout    *rollout.Controller
	appLogs    *rollout.LogStreams
	routes     *routes.Publisher
	visitors   *visitor.Service
}

// New connects to every dependency, applies migrations and binds the HTTP
// listener. If any step fails, everything opened so far is closed again.
func New(ctx context.Context, cfg *Config, logger *slog.Logger) (*Server, error) {
	s := &Server{logger: logger}
	if err := s.start(ctx, cfg); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// start runs the startup sequence. Order matters: the schema must be
// migrated before the listener accepts requests that would query it.
func (s *Server) start(ctx context.Context, cfg *Config) error {
	for _, w := range cfg.PlaintextWarnings() {
		s.logger.WarnContext(ctx, "connection without TLS allowed by NOOK_ALLOW_PLAINTEXT_INTERNAL", "connection", w)
	}
	if err := s.connect(ctx, cfg); err != nil {
		return err
	}
	migrateCtx, cancel := context.WithTimeout(ctx, cfg.MigrationTimeout)
	defer cancel()
	if err := postgres.Migrate(migrateCtx, s.pool, migrations.FS, s.logger); err != nil {
		return err
	}
	return s.listen(ctx, cfg)
}

// connect creates the Postgres pool and Redis client and waits, up to the
// startup timeout, until both answer.
func (s *Server) connect(ctx context.Context, cfg *Config) error {
	var err error
	if s.pool, err = postgres.NewPool(ctx, &cfg.Postgres, ServiceName); err != nil {
		return err
	}
	if s.redis, err = redis.NewClient(&cfg.Redis); err != nil {
		return err
	}
	startupCtx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	for _, c := range s.dependencyChecks() {
		if err := health.WaitUntil(startupCtx, s.logger, c, health.DefaultBackoff); err != nil {
			return fmt.Errorf("startup: %w", err)
		}
	}
	// One discovery attempt now, so a misconfigured issuer shows up in the
	// startup logs. Failure is not fatal: sign-in retries discovery on
	// demand, and API clients holding tokens never need the provider.
	s.provider = identity.NewProvider(&cfg.Identity, cfg.Identity.ResolveRedirectURL(cfg.PublicURLParsed()))
	if err := s.provider.Discover(startupCtx); err != nil {
		s.logger.WarnContext(ctx, "identity provider not reachable yet; sign-in will retry", "error", err.Error())
	}
	return nil
}

// dependencyChecks probes the dependencies the control plane cannot work
// without; they gate both startup and /readyz.
func (s *Server) dependencyChecks() []health.Check {
	return []health.Check{
		{Name: "postgres", Probe: s.pool.Ping},
		{Name: "redis", Probe: func(ctx context.Context) error { return s.redis.Ping(ctx).Err() }},
	}
}

// listen builds the services, the metrics registry and the router, and
// binds the listener.
func (s *Server) listen(ctx context.Context, cfg *Config) error {
	reg, err := metrics.NewRegistry(ServiceName, version.Get())
	if err != nil {
		return err
	}
	err = reg.Register(postgres.NewPoolCollector(s.pool))
	if err != nil {
		return fmt.Errorf("register postgres pool metrics: %w", err)
	}
	router, err := api.NewRouter(&api.Deps{ //nolint:contextcheck // middleware runs on each request's own context.
		Logger:           s.logger,
		Registry:         reg,
		HTTP:             cfg.HTTP,
		ReadinessChecks:  s.dependencyChecks(),
		ReadinessTimeout: cfg.ReadinessTimeout,
		StreamingRoutes:  []string{api.RouteBuildLog, api.RouteAppLogs},
	})
	if err != nil {
		return err
	}
	err = s.mountApplication(ctx, router, cfg, reg)
	if err != nil {
		return err
	}
	if s.http, err = httpserver.Listen(ctx, &cfg.HTTP, router, s.logger); err != nil {
		return err
	}
	s.logger.InfoContext(ctx, "nook-server is listening", "addr", s.http.Addr().String(),
		"tls", cfg.HTTP.TLSEnabled(), "public_url", cfg.PublicURL)
	return nil
}

// Addr returns the address the HTTP server is bound to.
func (s *Server) Addr() net.Addr {
	return s.http.Addr()
}

// GRPCAddr returns the address the agent gRPC server is bound to.
func (s *Server) GRPCAddr() net.Addr {
	return s.grpc.Addr()
}

// Instance returns this control-plane instance's ID.
func (s *Server) Instance() string {
	return s.instance
}

// IsLeader reports whether this instance runs the failure detector.
func (s *Server) IsLeader() bool {
	return s.elector.IsLeader()
}

// hubReadyTimeout bounds waiting for the command hub's Redis subscription.
const hubReadyTimeout = 10 * time.Second

// Serve runs the HTTP API, the agent gRPC endpoint, the command hub and
// the leader election (with the failure detector) until ctx is canceled,
// then shuts them all down. If one of them fails, the others are stopped
// too and the error is returned. Call Close afterwards.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	start := func(name string, fn func(context.Context) error) {
		wg.Go(func() {
			if err := fn(ctx); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", name, err)
				}
				mu.Unlock()
				cancel(err)
			}
		})
	}

	// The hub must be subscribed before agents connect, or commands
	// routed to this instance could be missed.
	start("command hub", s.hub.Run)
	select {
	case <-s.hub.Ready():
	case <-ctx.Done():
	case <-time.After(hubReadyTimeout):
		cancel(errors.New("command hub did not subscribe in time"))
	}
	start("agent gRPC", s.grpc.Serve)
	start("leader election", func(ctx context.Context) error {
		s.elector.Run(ctx, func(ctx context.Context, sess *leader.Session) {
			// Every query of the leader's loops runs on the lock connection
			// (fencing): a deposed leader cannot act.
			var loops sync.WaitGroup
			loops.Go(func() {
				s.rollout.RunLeader(ctx, func(ctx context.Context, fn func(rollout.DB) error) error {
					return sess.Do(ctx, func(conn *pgx.Conn) error { return fn(conn) })
				})
			})
			s.detector.Run(ctx, func(ctx context.Context, fn func(nodes.DB) error) error {
				return sess.Do(ctx, func(conn *pgx.Conn) error { return fn(conn) })
			})
			loops.Wait()
		})
		return nil
	})
	start("build dispatcher", s.dispatcher.Run)
	start("build janitor", func(ctx context.Context) error {
		s.janitor.Run(ctx)
		return nil
	})
	start("http", s.http.Serve)
	wg.Wait()
	return firstErr
}

// Close releases the database and Redis connections. It runs after the
// HTTP server has drained, so no request is cut off mid-query.
func (s *Server) Close() {
	if s.grpc != nil {
		s.grpc.Close()
	}
	if s.redis != nil {
		if err := s.redis.Close(); err != nil && !errors.Is(err, goredis.ErrClosed) {
			s.logger.Warn("closing redis client", "error", err.Error())
		}
		s.redis = nil
	}
	if s.pool != nil {
		s.pool.Close()
		s.pool = nil
	}
}
