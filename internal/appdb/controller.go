package appdb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Commander sends a command to a node's agent (agentlink.Hub).
type Commander interface {
	Dispatch(ctx context.Context, nodeID uuid.UUID, cmd *agentv1.Command, timeout time.Duration) (*agentv1.CommandResult, error)
}

// DB is the leader's lock connection (fencing: a deposed leader's queries
// fail).
type DB interface {
	store.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

// With runs fn on the leader's lock connection.
type With func(ctx context.Context, fn func(DB) error) error

// Deps are the controller's collaborators.
type Deps struct {
	Store     *store.Store
	Commander Commander
	CA        *pki.CA
	Keyring   *secrets.Keyring
	Apps      *apps.Service
	Objects   *objstore.Client
	Logger    *slog.Logger
	Metrics   prometheus.Registerer
	// NodeReservedMemoryMB is memory per node kept free of apps and the
	// database server (the scheduler's setting).
	NodeReservedMemoryMB int64
}

// Controller runs the app database server and the app databases on it.
type Controller struct {
	Deps
	cfg Config
	m   *metrics
	now func() time.Time

	// Leader-only state, reset when leadership is gained.
	mu            sync.Mutex
	lastMonitor   time.Time
	lastEndpoint  *agentv1.DatabaseEndpoint
	lastBroadcast time.Time
}

// Timing of the leader's decisions.
const (
	dispatchTimeout = 15 * time.Second
	// retryDelay spaces new attempts after a server failed to start.
	retryDelay = 30 * time.Second
	// resendAfter: commands for a starting or stopping server are sent
	// again after this long (agents ignore repeats while busy).
	resendAfter = time.Minute
	// backupStale: a backup claimed longer ago is considered lost.
	backupStale = 13 * time.Hour
	// tlsTTL and tlsRenewBefore govern the server's certificate.
	tlsTTL         = 90 * 24 * time.Hour
	tlsRenewBefore = 30 * 24 * time.Hour
	// broadcastEvery re-sends the endpoint to every agent.
	broadcastEvery = 5 * time.Minute
	// dumpGrace: dumps not finished this long after starting fail.
	dumpGrace = 7 * time.Hour
	batch     = 100
)

// New creates the controller; cfg must be valid (and resolved).
func New(d *Deps, cfg *Config) (*Controller, error) {
	m, err := newMetrics(d.Metrics, d.Store)
	if err != nil {
		return nil, err
	}
	return &Controller{Deps: *d, cfg: *cfg, m: m, now: time.Now}, nil
}

// Enabled reports whether app databases are configured.
func (c *Controller) Enabled() bool { return c.cfg.Enabled() }

// RunLeader runs the leader's pass every Interval until ctx ends.
func (c *Controller) RunLeader(ctx context.Context, with With) {
	if !c.cfg.Enabled() {
		return
	}
	c.mu.Lock()
	c.lastMonitor, c.lastEndpoint, c.lastBroadcast = time.Time{}, nil, time.Time{}
	c.mu.Unlock()
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.pass(ctx, with)
		}
	}
}

// followUp is work after the decisions: commands to agents, SQL on the
// database server and the short writes that record their outcome (again
// through with).
type followUp func(ctx context.Context, with With)

func (c *Controller) pass(ctx context.Context, with With) {
	var after []followUp
	err := with(ctx, func(db DB) error {
		var err error
		after, err = c.decide(ctx, db)
		return err
	})
	if err != nil && ctx.Err() == nil {
		c.Logger.ErrorContext(ctx, "app database pass failed", "error", err.Error())
	}
	for _, f := range after {
		if ctx.Err() != nil {
			return
		}
		f(ctx, with)
	}
}

// decide looks at the current server and plans what to do.
func (c *Controller) decide(ctx context.Context, db DB) ([]followUp, error) {
	q := store.New(db)
	var after []followUp
	if err := q.FailStaleDBDumps(ctx, c.now().Add(-dumpGrace)); err != nil {
		return nil, fmt.Errorf("fail stale dumps: %w", err)
	}
	if expired, err := q.ListExpiredDBDumps(ctx, batch); err != nil {
		return nil, fmt.Errorf("list expired dumps: %w", err)
	} else if len(expired) > 0 {
		after = append(after, func(ctx context.Context, with With) { c.deleteDumps(ctx, with, expired) })
	}
	old, err := q.ListUnstoppedOldDBServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list replaced servers: %w", err)
	}
	for i := range old {
		s := old[i]
		after = append(after, func(ctx context.Context, _ With) { _ = c.sendStop(ctx, &s, false, false) })
	}

	h, err := q.CurrentDBServerHealth(ctx)
	switch {
	case store.IsNotFound(err):
		f, nerr := c.planNext(ctx, db)
		if nerr != nil {
			return nil, nerr
		}
		after = append(after, f...)
		return append(after, c.endpointFollowUp(nil)), nil
	case err != nil:
		return nil, fmt.Errorf("read the database server: %w", err)
	}
	srv := h.AppDbServer
	if h.NodeStatus == "dead" || h.NodeStatus == "removed" {
		f, ferr := c.failOver(ctx, db, &srv, h.DeadAt)
		if ferr != nil {
			return nil, ferr
		}
		return append(append(after, f...), c.endpointFollowUp(nil)), nil
	}
	switch srv.State {
	case store.AppDbServerStateStarting:
		if srv.StartSentAt == nil || c.now().Sub(*srv.StartSentAt) > resendAfter {
			after = append(after, func(ctx context.Context, with With) { c.sendStart(ctx, with, &srv) })
		}
		return append(after, c.endpointFollowUp(nil)), nil
	case store.AppDbServerStateStopping:
		// Sent again until the agent accepts it (it is busy while
		// starting), then only if it never reports back.
		if srv.StopSentAt == nil || c.now().Sub(*srv.StopSentAt) > resendAfter {
			after = append(after, func(ctx context.Context, with With) { c.stopForMove(ctx, with, &srv) })
		}
		return append(after, c.endpointFollowUp(nil)), nil
	case store.AppDbServerStateRunning:
	default:
		return after, nil
	}
	running, err := c.planRunning(ctx, q, &srv)
	if err != nil {
		return nil, err
	}
	return append(append(after, running...), c.endpointFollowUp(endpointOf(&srv))), nil
}

// planRunning plans the work on a running server: databases to create,
// drop or re-point, the base backup, monitoring and the certificate.
func (c *Controller) planRunning(ctx context.Context, q *store.Queries, srv *store.AppDbServer) ([]followUp, error) {
	var after []followUp
	create, err := q.ListAppDatabasesToProvision(ctx, batch)
	if err != nil {
		return nil, fmt.Errorf("list databases to create: %w", err)
	}
	drop, err := q.ListAppDatabasesToDrop(ctx, batch)
	if err != nil {
		return nil, fmt.Errorf("list databases to drop: %w", err)
	}
	all, err := q.ListAppDatabases(ctx)
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	var repoint []store.ListAppDatabasesRow
	for i := range all {
		d := &all[i]
		if d.AppDatabase.State == store.AppDatabaseStateReady && (d.AppDatabase.ServerGeneration == nil || *d.AppDatabase.ServerGeneration != srv.Generation) {
			repoint = append(repoint, *d)
		}
	}
	if len(create)+len(drop)+len(repoint) > 0 {
		after = append(after, func(ctx context.Context, with With) { c.reconcileDatabases(ctx, with, srv, create, drop, repoint) })
	}
	if srv.LastBackupAt == nil || c.now().Sub(*srv.LastBackupAt) >= c.cfg.BackupInterval {
		claimed, claimErr := q.DBServerBackupStarted(ctx, store.DBServerBackupStartedParams{ID: srv.ID, StaleBefore: ptr(c.now().Add(-backupStale))})
		switch {
		case claimErr == nil:
			after = append(after, func(ctx context.Context, with With) { c.sendBackup(ctx, with, &claimed) })
		case !store.IsNotFound(claimErr):
			return nil, fmt.Errorf("claim backup: %w", claimErr)
		}
	}
	c.mu.Lock()
	monitor := c.now().Sub(c.lastMonitor) >= c.cfg.MonitorInterval
	if monitor {
		c.lastMonitor = c.now()
	}
	c.mu.Unlock()
	if monitor {
		after = append(after, func(ctx context.Context, with With) { c.monitor(ctx, with, srv) })
	}
	if srv.TlsExpiresAt == nil || srv.TlsExpiresAt.Sub(c.now()) < tlsRenewBefore {
		after = append(after, func(ctx context.Context, with With) { c.renewTLS(ctx, with, srv) })
	}
	return after, nil
}

// failOver replaces a server whose node died: it is fenced (apps never
// use it again) and the next generation is restored from the backups on
// another node.
func (c *Controller) failOver(ctx context.Context, db DB, srv *store.AppDbServer, deadAt time.Time) ([]followUp, error) {
	q := store.New(db)
	if _, err := q.FenceDBServer(ctx, srv.ID); err != nil {
		if store.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fence the server: %w", err)
	}
	at := deadAt
	c.Logger.WarnContext(ctx, "app database server's node died; restoring it on another node",
		"server", srv.ID.String(), "generation", srv.Generation, "node", srv.NodeName)
	next, err := c.createServer(ctx, db, srv, "restore", "failover", at, nil)
	if err != nil {
		var noNode noNodeError
		if errors.As(err, &noNode) {
			c.Logger.ErrorContext(ctx, "no node can take over the app database server; retrying", "reason", err.Error())
			return nil, nil
		}
		return nil, err
	}
	return []followUp{func(ctx context.Context, with With) { c.sendStart(ctx, with, &next) }}, nil
}

// planNext creates a server when databases exist but no server is
// current: the first one, the next one after a planned stop, or a retry
// after a failure.
func (c *Controller) planNext(ctx context.Context, db DB) ([]followUp, error) {
	q := store.New(db)
	n, err := q.CountAppDatabases(ctx)
	if err != nil {
		return nil, fmt.Errorf("count databases: %w", err)
	}
	if n == 0 {
		return nil, nil // nothing runs until an app asks for a database
	}
	latest, err := q.LatestDBServer(ctx)
	var prev *store.AppDbServer
	switch {
	case err == nil:
		prev = &latest
	case !store.IsNotFound(err):
		return nil, fmt.Errorf("read the latest server: %w", err)
	}
	mode, cause, at, prefer := "init", "first", c.now(), (*uuid.UUID)(nil)
	if prev != nil {
		ran, ranErr := q.AnyDBServerRan(ctx)
		if ranErr != nil {
			return nil, fmt.Errorf("read server history: %w", ranErr)
		}
		if ran {
			mode = "restore"
		}
		switch {
		case prev.State == store.AppDbServerStateFenced && prev.FinalWal != "":
			cause, prefer = "planned", prev.MoveToNodeID
			if prev.StopRequestedAt != nil {
				at = *prev.StopRequestedAt
			}
		case prev.State == store.AppDbServerStateFenced:
			cause = "failover"
		default:
			cause = "retry"
			if c.now().Sub(prev.UpdatedAt) < retryDelay {
				return nil, nil
			}
		}
	}
	next, err := c.createServer(ctx, db, prev, mode, cause, at, prefer)
	if err != nil {
		var noNode noNodeError
		if errors.As(err, &noNode) {
			c.Logger.WarnContext(ctx, "no node can host the app database server yet", "reason", err.Error())
			return nil, nil
		}
		return nil, err
	}
	return []followUp{func(ctx context.Context, with With) { c.sendStart(ctx, with, &next) }}, nil
}

// stopForMove asks for the clean stop of a planned failover and records
// that the agent accepted it.
func (c *Controller) stopForMove(ctx context.Context, with With, srv *store.AppDbServer) {
	if !c.sendStop(ctx, srv, true, false) {
		return
	}
	_ = with(ctx, func(db DB) error { return store.New(db).DBServerStopSent(ctx, srv.ID) })
}

// endpointOf is where apps reach a running server.
func endpointOf(s *store.AppDbServer) *agentv1.DatabaseEndpoint {
	if s.Address == "" || s.Port == 0 {
		return nil
	}
	return &agentv1.DatabaseEndpoint{Address: s.Address, Port: s.Port}
}

// CurrentEndpoint is the endpoint agents allow apps to reach (nil: none),
// for agents that (re)connect.
func (c *Controller) CurrentEndpoint(ctx context.Context) *agentv1.DatabaseEndpoint {
	if !c.cfg.Enabled() {
		return nil
	}
	s, err := c.Store.CurrentDBServer(ctx)
	if err != nil || s.State != store.AppDbServerStateRunning {
		return nil
	}
	return endpointOf(&s)
}

// endpointFollowUp sends the endpoint to every agent when it changed (and
// every broadcastEvery), so app containers can reach the current server
// and no other.
func (c *Controller) endpointFollowUp(ep *agentv1.DatabaseEndpoint) followUp {
	return func(ctx context.Context, _ With) {
		c.mu.Lock()
		same := sameEndpoint(c.lastEndpoint, ep) && c.now().Sub(c.lastBroadcast) < broadcastEvery && !c.lastBroadcast.IsZero()
		c.mu.Unlock()
		if same {
			return
		}
		nodes, err := c.Store.ListLiveNodes(ctx)
		if err != nil {
			c.Logger.WarnContext(ctx, "could not list nodes for the database endpoint", "error", err.Error())
			return
		}
		var wg sync.WaitGroup
		for _, n := range nodes {
			if n.Status == store.NodeStatusDead || n.Status == store.NodeStatusRemoved || n.Status == store.NodeStatusJoining {
				continue
			}
			wg.Go(func() {
				// One command per node: Dispatch fills in its ID.
				cmd := &agentv1.Command{Kind: &agentv1.Command_SetDatabaseEndpoint{SetDatabaseEndpoint: &agentv1.SetDatabaseEndpointCommand{Endpoint: ep}}}
				if res, err := c.Commander.Dispatch(ctx, n.ID, cmd, dispatchTimeout); err == nil && res.GetError() != nil {
					c.Logger.WarnContext(ctx, "an agent refused the database endpoint", "node", n.Name, "error", res.GetError().GetMessage())
				}
			})
		}
		wg.Wait()
		c.mu.Lock()
		c.lastEndpoint, c.lastBroadcast = ep, c.now()
		c.mu.Unlock()
	}
}

func sameEndpoint(a, b *agentv1.DatabaseEndpoint) bool {
	return a.GetAddress() == b.GetAddress() && a.GetPort() == b.GetPort()
}

// adminHost is the host the control plane connects to.
func (c *Controller) adminHost(s *store.AppDbServer) string {
	if c.cfg.AdminHost != "" {
		return c.cfg.AdminHost
	}
	return s.Address
}

// connect opens a superuser connection to the server.
func (c *Controller) connect(ctx context.Context, s *store.AppDbServer) (*admin, error) {
	pw, err := c.Keyring.Open(int(s.PasswordKeyVersion), secrets.DatabaseSuperuserAAD(s.ID), s.SuperuserPassword)
	if err != nil {
		return nil, fmt.Errorf("decrypt the server's password: %w", err)
	}
	return connectAdmin(ctx, c.adminHost(s), s.Port, string(pw), c.CA.Pool())
}

func validAddr(a string) bool {
	_, err := netip.ParseAddr(a)
	return err == nil
}

func ptr[T any](v T) *T { return &v }
