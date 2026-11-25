package builds

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"uuid"

	"github.com/prometheus/client_golang/prometheus"
	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Commander sends a command to a node's agent, wherever it is connected
// (agentlink.Hub).
type Commander interface {
	Dispatch(ctx context.Context, nodeID uuid.UUID, cmd *agentv1.Command, timeout time.Duration) (*agentv1.CommandResult, error)
}

// HeartbeatSource returns a node's latest heartbeat (nodes.Registry).
type HeartbeatSource interface {
	LatestHeartbeat(ctx context.Context, nodeID uuid.UUID) (*nodes.Sample, error)
}

// Deps are the dispatcher's collaborators.
type Deps struct {
	Store      *store.Store
	Redis      *goredis.Client
	Commander  Commander
	Heartbeats HeartbeatSource
	Apps       *apps.Service
	Objects    *objstore.Client
	Issuer     *registry.Issuer
	Registry   *registry.Client
	// RegistryAddr is the registry host:port nodes push to.
	RegistryAddr string
	Logs         *Logs
	Logger       *slog.Logger
	Metrics      prometheus.Registerer
}

// Dispatcher consumes the build queue. Every control-plane instance runs
// one; each queued deployment is owned by exactly one live instance,
// which places its build on a node and follows it to the end.
type Dispatcher struct {
	Deps
	cfg      Config
	instance string
	metrics  *metrics

	mu       sync.Mutex
	watchers map[uuid.UUID]chan struct{}
	owned    chan struct{}
}

// NewDispatcher returns a dispatcher for this instance.
func NewDispatcher(d *Deps, cfg *Config, instance string) (*Dispatcher, error) {
	m, err := newMetrics(d.Metrics)
	if err != nil {
		return nil, err
	}
	return &Dispatcher{Deps: *d, cfg: *cfg, instance: instance, metrics: m,
		watchers: map[uuid.UUID]chan struct{}{}, owned: make(chan struct{}, maxOwned)}, nil
}

// Run consumes jobs until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) error {
	if err := ensureGroup(ctx, d.Redis); err != nil {
		return err
	}
	sub := d.Redis.Subscribe(ctx, wakeChannel)
	defer func() { _ = sub.Close() }()
	if _, err := sub.Receive(ctx); err != nil {
		return fmt.Errorf("subscribe %s: %w", wakeChannel, err)
	}
	go d.routeWakes(ctx, sub.Channel())

	var wg sync.WaitGroup
	defer wg.Wait()
	lastReclaim := time.Time{}
	for ctx.Err() == nil {
		free := int64(cap(d.owned) - len(d.owned))
		if free == 0 {
			if !sleep(ctx, d.cfg.TickInterval) {
				break
			}
			continue
		}
		var jobs []job
		var err error
		if time.Since(lastReclaim) >= d.cfg.ClaimTimeout/2 {
			lastReclaim = time.Now()
			if jobs, err = reclaim(ctx, d.Redis, d.instance, d.cfg.ClaimTimeout); err == nil && len(jobs) > 0 {
				d.Logger.InfoContext(ctx, "reclaimed build jobs from a silent instance", "jobs", len(jobs))
			}
		}
		if err == nil && len(jobs) == 0 {
			jobs, err = readNew(ctx, d.Redis, d.instance, min(d.cfg.TickInterval, 2*time.Second), free)
		}
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			d.Logger.WarnContext(ctx, "build queue unavailable", "error", err.Error())
			if !sleep(ctx, d.cfg.TickInterval) {
				break
			}
			continue
		}
		for _, j := range jobs {
			d.owned <- struct{}{}
			wg.Go(func() {
				defer func() { <-d.owned }()
				d.handle(ctx, j)
			})
		}
	}
	return nil
}

func (d *Dispatcher) routeWakes(ctx context.Context, ch <-chan *goredis.Message) {
	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-ch:
			if !ok {
				return
			}
			id, err := uuid.Parse(m.Payload)
			if err != nil {
				continue
			}
			d.mu.Lock()
			w := d.watchers[id]
			d.mu.Unlock()
			if w != nil {
				select {
				case w <- struct{}{}:
				default:
				}
			}
		}
	}
}

// handle owns one job until its deployment is finished. Duplicate jobs
// (the deployment is owned elsewhere) are acknowledged at once; a job
// whose owner dies stays pending and is reclaimed by another instance.
func (d *Dispatcher) handle(ctx context.Context, j job) {
	if !j.valid {
		_ = ack(ctx, d.Redis, j.entryID)
		return
	}
	id := j.deploymentID
	ok, err := acquireOwner(ctx, d.Redis, id, d.instance)
	if err != nil {
		d.Logger.WarnContext(ctx, "could not take a build job", "deployment", id.String(), "error", err.Error())
		return
	}
	if !ok {
		_ = ack(ctx, d.Redis, j.entryID)
		return
	}
	defer releaseOwner(context.WithoutCancel(ctx), d.Redis, id, d.instance)
	wake := make(chan struct{}, 1)
	d.mu.Lock()
	d.watchers[id] = wake
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.watchers, id)
		d.mu.Unlock()
	}()

	ticker := time.NewTicker(d.cfg.TickInterval)
	defer ticker.Stop()
	for {
		done, err := d.step(ctx, id)
		if err != nil && ctx.Err() == nil {
			d.Logger.WarnContext(ctx, "build step failed; will retry", "deployment", id.String(), "error", err.Error())
		}
		if done {
			if err := ack(ctx, d.Redis, j.entryID); err != nil {
				d.Logger.WarnContext(ctx, "could not acknowledge build job", "error", err.Error())
			}
			return
		}
		select {
		case <-ctx.Done():
			// Shutting down: the job stays pending and another instance
			// reclaims it; the build itself keeps running on its node.
			return
		case <-wake:
		case <-ticker.C:
		}
		if still, err := renewOwner(ctx, d.Redis, id, d.instance); err != nil || !still {
			if err == nil {
				d.Logger.WarnContext(ctx, "lost ownership of a deployment", "deployment", id.String())
			}
			return
		}
		_ = touch(ctx, d.Redis, d.instance, j.entryID)
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
