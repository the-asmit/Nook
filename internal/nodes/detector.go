package nodes

import (
	"context"
	"fmt"
	"log/slog"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/platform/metrics"
	"github.com/the-asmit/nook/internal/store"
)

// healthyStatus is where a node goes when its heartbeats are current:
// draining if an admin asked for it, ready otherwise.
func healthyStatus(draining bool) store.NodeStatus {
	if draining {
		return store.NodeStatusDraining
	}
	return store.NodeStatusReady
}

// observation is everything the health decision depends on.
type observation struct {
	status   store.NodeStatus
	draining bool
	joinedAt time.Time
	// lastSeen is the latest heartbeat time; nil if none ever arrived.
	lastSeen *time.Time
	now      time.Time
}

// decide returns the status a node should have, and why. It is a pure
// function of the observation so it can be tested exhaustively.
//
//	heartbeat age < 3 intervals          -> ready (or draining)
//	3 intervals <= age < dead threshold  -> suspect
//	age >= dead threshold                -> dead
//
// A node that never sent a heartbeat stays "joining" until the dead
// threshold has passed since it joined.
func decide(o *observation, cfg *Config) (store.NodeStatus, string) {
	if o.lastSeen == nil {
		if o.now.Sub(o.joinedAt) >= cfg.DeadAfter {
			return store.NodeStatusDead, fmt.Sprintf("no heartbeat in %s since joining", cfg.DeadAfter)
		}
		return o.status, ""
	}
	age := o.now.Sub(*o.lastSeen)
	switch {
	case age < cfg.SuspectAfter():
		return healthyStatus(o.draining), "heartbeats received"
	case age < cfg.DeadAfter:
		return store.NodeStatusSuspect, fmt.Sprintf("no heartbeat for %s", age.Truncate(time.Second))
	default:
		return store.NodeStatusDead, fmt.Sprintf("no heartbeat for %s", age.Truncate(time.Second))
	}
}

// Detector moves nodes between health states. Exactly one control-plane
// instance (the leader) runs it, so transitions have a single writer.
type Detector struct {
	heartbeats *Heartbeats
	publisher  *Publisher
	clock      Clock
	cfg        Config
	logger     *slog.Logger
	gauge      *prometheus.GaugeVec
}

// NewDetector returns a failure detector and registers its metrics.
func NewDetector(hb *Heartbeats, pub *Publisher, clock Clock, cfg Config, reg prometheus.Registerer, logger *slog.Logger) (*Detector, error) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metrics.Namespace, Name: "nodes",
		Help: "Nodes by status, as last evaluated by the failure detector (set on the leader only).",
	}, []string{"status"})
	if err := reg.Register(gauge); err != nil {
		return nil, fmt.Errorf("register node metrics: %w", err)
	}
	return &Detector{heartbeats: hb, publisher: pub, clock: clock, cfg: cfg, logger: logger, gauge: gauge}, nil
}

// DB is a database handle the detector can query and open transactions
// on: in production the leader's lock connection (see leader.Session), so
// that a deposed leader's writes fail; a pool in tests.
type DB interface {
	store.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Run evaluates nodes every DetectorInterval until ctx is done. Each pass
// runs inside with, which supplies the database handle (the leader's lock
// connection).
func (d *Detector) Run(ctx context.Context, with func(context.Context, func(DB) error) error) {
	ticker := time.NewTicker(d.cfg.DetectorInterval)
	defer ticker.Stop()
	for {
		err := with(ctx, func(db DB) error { return d.Tick(ctx, db) })
		if err != nil && ctx.Err() == nil {
			d.logger.ErrorContext(ctx, "failure detector pass failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick evaluates every live node once and applies the transitions due,
// using db for every query.
func (d *Detector) Tick(ctx context.Context, db DB) error {
	ctx, cancel := context.WithTimeout(ctx, max(d.cfg.DetectorInterval, 5*time.Second))
	defer cancel()

	live, err := store.New(db).ListLiveNodes(ctx)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	ids := make([]uuid.UUID, len(live))
	for i := range live {
		ids[i] = live[i].ID
	}
	seen, err := d.heartbeats.LastSeen(ctx, ids)
	if err != nil {
		return err
	}
	now, err := d.clock.Now(ctx)
	if err != nil {
		return err
	}

	counts := map[store.NodeStatus]int{}
	for i := range live {
		n := &live[i]
		obs := observation{status: n.Status, draining: n.Draining, joinedAt: n.JoinedAt, lastSeen: latest(n.LastHeartbeatAt, seen[n.ID]), now: now}
		target, reason := decide(&obs, &d.cfg)
		if target != n.Status {
			ok, err := d.transition(ctx, db, n, target, reason, obs.lastSeen)
			if err != nil {
				return err
			}
			if ok {
				n.Status = target
			}
		}
		counts[n.Status]++
	}
	for _, s := range store.AllNodeStatusValues() {
		d.gauge.WithLabelValues(string(s)).Set(float64(counts[s]))
	}
	return nil
}

func transitionTx(ctx context.Context, db DB, n *store.ListLiveNodesRow, from, to store.NodeStatus, reason string, seen *time.Time) (*Event, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := store.New(tx)
	rows, err := q.TransitionNode(ctx, store.TransitionNodeParams{ID: n.ID, FromStatus: from, ToStatus: to, SeenAt: seen})
	if err != nil || rows == 0 {
		return nil, err
	}
	ev, err := recordTransition(ctx, q, n.ID, n.Name, &from, to, reason)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return ev, nil
}

// latest returns the later of the persisted and the Redis heartbeat time.
func latest(persisted *time.Time, redis time.Time) *time.Time {
	switch {
	case redis.IsZero():
		return persisted
	case persisted == nil || redis.After(*persisted):
		return &redis
	default:
		return persisted
	}
}

// transition applies one compare-and-set state change with its event.
// It reports false if the node changed concurrently (an admin drained or
// removed it), in which case the next pass re-evaluates it.
func (d *Detector) transition(ctx context.Context, db DB, n *store.ListLiveNodesRow, to store.NodeStatus, reason string, seen *time.Time) (bool, error) {
	from := n.Status
	ev, err := transitionTx(ctx, db, n, from, to, reason, seen)
	if err != nil {
		return false, fmt.Errorf("transition node %s: %w", n.Name, err)
	}
	if ev == nil {
		return false, nil
	}
	d.logger.InfoContext(ctx, "node state changed", "node", n.Name, "node_id", n.ID.String(),
		"from", string(from), "to", string(to), "reason", reason)
	if err := d.publisher.Event(ctx, ev); err != nil {
		d.logger.WarnContext(ctx, "publish node event", "error", err.Error())
	}
	return true, nil
}
