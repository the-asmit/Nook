package server

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/builds"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/rollout"
	"github.com/the-asmit/nook/internal/routes"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/visitor"
)

// startBuilds builds the app, build and release pipeline: the secrets
// keyring (verified against the database), object storage, the registry
// token issuer and client, the apps service, the deployment queue and its
// dispatcher, the rollout controller, build and app logs, the janitor and
// registry maintenance windows.
func (s *Server) startBuilds(ctx context.Context, st *store.Store, cfg *Config, nodeRegistry *nodes.Registry, reg prometheus.Registerer) error {
	keyring, err := cfg.Secrets.Keyring()
	if err != nil {
		return fmt.Errorf("NOOK_SECRETS_KEY: %w", err)
	}
	verifyCtx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	if verifyErr := secrets.Verify(verifyCtx, st, keyring); verifyErr != nil {
		return verifyErr
	}
	objects, err := objstore.New(&cfg.Storage, nil)
	if err != nil {
		return err
	}
	s.objects = objects
	issuer := registry.NewIssuer(s.ca, cfg.Registry.Issuer, cfg.Registry.Service)
	regClient := registry.NewClient(&cfg.Registry, issuer, s.ca)
	queue := builds.NewQueue(s.redis)
	s.routes = routes.NewPublisher(s.redis)
	s.apps = apps.NewService(st, objects, queue, keyring, s.routes, cfg.Apps)
	s.visitors = visitor.New(st, keyring, cfg.AppsBase(), cfg.Apps.AllowPublicApps, &cfg.Visitor)
	s.logs = builds.NewLogs(s.redis, objects, st, s.logger)
	s.rollout = rollout.New(&rollout.Deps{
		Store: st, Commander: s.hub, Keyring: keyring, Issuer: issuer, RegistryAddr: cfg.Registry.Addr,
		Notes: s.logs, Quotas: s.apps, Wake: queue.Wake, Routes: s.routes, Scheduler: cfg.Scheduler, Logger: s.logger,
	}, &cfg.Rollout)
	s.appLogs = rollout.NewLogStreams(s.redis, s.hub, &cfg.Rollout, s.logger)
	deps := &builds.Deps{
		Store: st, Redis: s.redis, Commander: s.hub, Heartbeats: nodeRegistry, Apps: s.apps,
		Objects: objects, Issuer: issuer, Registry: regClient, RegistryAddr: cfg.Registry.Addr,
		Logs: s.logs, Releases: s.rollout, Logger: s.logger, Metrics: reg,
	}
	if s.dispatcher, err = builds.NewDispatcher(deps, &cfg.Builds, s.instance); err != nil {
		return err
	}
	// The janitor is leader-only work; it runs on the instance that holds
	// the failure detector's lock.
	s.janitor = builds.NewJanitor(deps, queue, &cfg.Builds, func() bool { return s.elector != nil && s.elector.IsLeader() })
	s.janitor.Also(s.visitors.Cleanup)
	s.gcWindow = builds.NewGCWindow(st, s.redis)
	return nil
}

// runtimeEvents routes what agents report about app instances and logs.
type runtimeEvents struct {
	*rollout.Controller
	*rollout.LogStreams
}
