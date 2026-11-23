package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/platform/health"
	"github.com/the-asmit/nook/internal/platform/httpserver"
	"github.com/the-asmit/nook/internal/platform/metrics"
	"github.com/the-asmit/nook/internal/platform/postgres"
	"github.com/the-asmit/nook/internal/platform/redis"
	"github.com/the-asmit/nook/internal/server/api"
	"github.com/the-asmit/nook/internal/version"
	"github.com/the-asmit/nook/migrations"
)

// ServiceName identifies the control plane in logs, metrics and
// pg_stat_activity.
const ServiceName = "nook-server"

// Server is a started control plane: dependencies connected, schema
// migrated and the HTTP listener bound.
type Server struct {
	logger *slog.Logger
	pool   *pgxpool.Pool
	redis  *goredis.Client
	http   *httpserver.Server
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

// listen builds the metrics registry and router and binds the listener.
func (s *Server) listen(ctx context.Context, cfg *Config) error {
	reg, err := metrics.NewRegistry(ServiceName, version.Get())
	if err != nil {
		return err
	}
	err = reg.Register(postgres.NewPoolCollector(s.pool))
	if err != nil {
		return fmt.Errorf("register postgres pool metrics: %w", err)
	}
	router, err := api.NewRouter(&api.Deps{
		Logger:           s.logger,
		Registry:         reg,
		HTTP:             cfg.HTTP,
		ReadinessChecks:  s.dependencyChecks(),
		ReadinessTimeout: cfg.ReadinessTimeout,
	})
	if err != nil {
		return err
	}
	if s.http, err = httpserver.Listen(ctx, &cfg.HTTP, router, s.logger); err != nil {
		return err
	}
	s.logger.InfoContext(ctx, "nook-server is listening", "addr", s.http.Addr().String(), "tls", cfg.HTTP.TLSEnabled())
	return nil
}

// Addr returns the address the HTTP server is bound to.
func (s *Server) Addr() net.Addr {
	return s.http.Addr()
}

// Serve handles requests until ctx is canceled, then drains in-flight
// requests. Call Close afterwards to release the connection pools.
func (s *Server) Serve(ctx context.Context) error {
	if err := s.http.Serve(ctx); err != nil {
		return fmt.Errorf("serve http: %w", err)
	}
	return nil
}

// Close releases the database and Redis connections. It runs after the
// HTTP server has drained, so no request is cut off mid-query.
func (s *Server) Close() {
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
