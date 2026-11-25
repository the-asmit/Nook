package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/agentlink"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/device"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/leader"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/ratelimit"
	"github.com/the-asmit/nook/internal/server/api"
	"github.com/the-asmit/nook/internal/server/web"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// mountApplication wires the services into the JSON API, the HTML pages
// and the agent-facing gRPC endpoint.
func (s *Server) mountApplication(ctx context.Context, router gin.IRouter, cfg *Config, reg prometheus.Registerer) error {
	st := store.NewStore(s.pool)
	site := auth.NewSite(cfg.PublicURLParsed())
	sessions := auth.NewSessions(st, cfg.Auth)
	tokens := auth.NewAPITokens(st)
	authenticator := auth.NewAuthenticator(sessions, tokens, site, s.logger)
	workspaces := workspace.NewService(st, cfg.InvitationTTL)
	devices := device.NewService(st, tokens, cfg.Device)
	limiter := ratelimit.New(s.redis)

	registry, err := s.startNodes(ctx, st, cfg, limiter, reg)
	if err != nil {
		return err
	}
	publicHost := cfg.PublicURLParsed().Hostname()
	api.RegisterV1(router, &api.V1Deps{
		Logger: s.logger, Store: st, Auth: authenticator, Tokens: tokens,
		Workspaces: workspaces, Devices: devices, Limiter: limiter,
		VerificationURL: site.Origin + "/device",
		Admin:           identity.NewAdmin(st), Nodes: registry, Hub: s.hub,
		AgentServer: cfg.GRPC.ResolvePublicAddr(publicHost), CAHash: s.ca.Fingerprint(),
		Apps: s.apps, Logs: s.logs, GCWindow: s.gcWindow, RegistryGCSecret: cfg.Registry.GCSecret,
		RegistryAddr: cfg.Registry.Addr, MaxSourceBytes: cfg.Apps.MaxSourceBytes,
	})
	pages, err := web.New(&web.Deps{
		Logger: s.logger, Store: st, Auth: authenticator,
		Flows: identity.NewFlows(s.redis), Provider: s.provider,
		SignIn:  identity.NewService(st, sessions, identity.NewPolicy(&cfg.Identity), s.logger),
		Devices: devices, Workspaces: workspaces, Limiter: limiter,
		ProviderName: cfg.Identity.ProviderName, PublicURL: site.Origin,
	})
	if err != nil {
		return err
	}
	pages.Register(router)
	return nil
}

// startNodes loads the CA and builds the node registry, the command hub,
// the failure detector with its leader election, and the gRPC listener.
func (s *Server) startNodes(ctx context.Context, st *store.Store, cfg *Config, limiter *ratelimit.Limiter, reg prometheus.Registerer) (*nodes.Registry, error) {
	ca, created, err := pki.LoadOrCreateCA(cfg.GRPC.CAPath)
	if err != nil {
		return nil, fmt.Errorf("agent CA: %w", err)
	}
	s.ca = ca
	s.logger.InfoContext(ctx, "agent certificate authority ready", "path", cfg.GRPC.CAPath, "created", created,
		"fingerprint", ca.Fingerprint())

	clock := nodes.RedisClock{Client: s.redis}
	hb := nodes.NewHeartbeats(s.redis, clock)
	pub := nodes.NewPublisher(s.redis)
	registry := nodes.NewRegistry(st, ca, hb, pub, cfg.Nodes, s.logger)

	// The instance ID addresses this process in command routing; a random
	// one per start means a restarted instance never receives commands
	// meant for its previous life.
	s.instance = "cp-" + strings.ToLower(rand.Text())
	s.hub = agentlink.NewHub(s.instance, s.redis, cfg.Nodes.SuspectAfter(), s.logger.With("instance", s.instance))

	if buildsErr := s.startBuilds(ctx, st, cfg, registry, reg); buildsErr != nil {
		return nil, buildsErr
	}
	if s.detector, err = nodes.NewDetector(hb, pub, clock, cfg.Nodes, reg, s.logger); err != nil {
		return nil, err
	}
	if s.elector, err = leader.New("failure_detector", leader.FailureDetectorLockID, s.pool.Config().ConnConfig,
		cfg.LeaderInterval, reg, s.logger.With("instance", s.instance)); err != nil {
		return nil, err
	}

	publicHost := cfg.PublicURLParsed().Hostname()
	s.grpc, err = agentlink.Listen(ctx, cfg.GRPC.Addr, cfg.GRPC.CertificateNames(publicHost), &agentlink.Deps{
		Registry: registry, Builds: s.dispatcher, Hub: s.hub, CA: ca, Limiter: limiter, Metrics: reg, Logger: s.logger,
	})
	if err != nil {
		return nil, err
	}
	s.logger.InfoContext(ctx, "agent gRPC endpoint listening", "addr", s.grpc.Addr().String(),
		"public_addr", cfg.GRPC.ResolvePublicAddr(publicHost), "instance", s.instance)
	return registry, nil
}
