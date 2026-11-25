package server

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/builds"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/store"
)

// startBuilds builds the app and build pipeline: object storage, the
// registry token issuer and client, the apps service, the build queue and
// its dispatcher, build logs, the janitor and registry maintenance windows.
func (s *Server) startBuilds(_ context.Context, st *store.Store, cfg *Config, nodeRegistry *nodes.Registry, reg prometheus.Registerer) error {
	objects, err := objstore.New(&cfg.Storage, nil)
	if err != nil {
		return err
	}
	s.objects = objects
	issuer := registry.NewIssuer(s.ca, cfg.Registry.Issuer, cfg.Registry.Service)
	regClient := registry.NewClient(&cfg.Registry, issuer, s.ca)
	queue := builds.NewQueue(s.redis)
	s.apps = apps.NewService(st, objects, queue, cfg.Apps)
	s.logs = builds.NewLogs(s.redis, objects, st, s.logger)
	deps := &builds.Deps{
		Store: st, Redis: s.redis, Commander: s.hub, Heartbeats: nodeRegistry, Apps: s.apps,
		Objects: objects, Issuer: issuer, Registry: regClient, RegistryAddr: cfg.Registry.Addr,
		Logs: s.logs, Logger: s.logger, Metrics: reg,
	}
	if s.dispatcher, err = builds.NewDispatcher(deps, &cfg.Builds, s.instance); err != nil {
		return err
	}
	// The janitor is leader-only work; it runs on the instance that holds
	// the failure detector's lock.
	s.janitor = builds.NewJanitor(deps, queue, &cfg.Builds, func() bool { return s.elector != nil && s.elector.IsLeader() })
	s.gcWindow = builds.NewGCWindow(st, s.redis)
	return nil
}
