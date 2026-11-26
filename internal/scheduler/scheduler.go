// Package scheduler places app instances on nodes.
//
// A node can take an instance when it is ready, not draining, publishes
// apps on an advertise address and has enough unreserved memory and CPU.
// A node's reservation is the sum of the limits of the instances placed
// on it that still hold resources (starting, healthy, unhealthy or
// stopping), so placement never depends on how busy an app happens to
// be right now. Among the nodes that fit, the scheduler picks the best
// fit: the node left with the least free memory, which keeps large holes
// free for large apps; ties go to the node with fewer instances.
//
// Placement runs in one transaction that locks every schedulable node row
// (in a fixed order) before reading reservations and inserting the
// instance, so two placements racing for the last capacity of a node are
// serialized and the second one sees the first one's reservation.
//
// Two options refine it. A placement may prefer a node (an app waking up
// resumes its sleeping instance where its container and image still are,
// if that node has room). And when nothing fits, a placement may evict:
// on a single node, the least recently used running apps that may sleep
// and have been idle long enough are put to sleep, in the same
// transaction, until the new instance fits (see ChooseEviction).
package scheduler

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/store"
)

// Config holds what the scheduler keeps free on every node.
type Config struct {
	// ReservedMemoryMB is memory per node not given to apps (the agent,
	// the Docker engine, builds' headroom).
	ReservedMemoryMB int64 `env:"NOOK_SCHEDULER_NODE_RESERVED_MEMORY_MB" envDefault:"512"`
	// ReservedMillicores is CPU per node not given to apps.
	ReservedMillicores int64 `env:"NOOK_SCHEDULER_NODE_RESERVED_MILLICORES" envDefault:"250"`
	// EvictMinIdle is how long an app must have gone without requests
	// before it may be put to sleep to make room for another.
	EvictMinIdle time.Duration `env:"NOOK_SCHEDULER_EVICT_MIN_IDLE" envDefault:"1m"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	return errors.Join(
		config.CheckRange("NOOK_SCHEDULER_NODE_RESERVED_MEMORY_MB", c.ReservedMemoryMB, 0, 1<<20),
		config.CheckRange("NOOK_SCHEDULER_NODE_RESERVED_MILLICORES", c.ReservedMillicores, 0, 1<<20),
		config.CheckDuration("NOOK_SCHEDULER_EVICT_MIN_IDLE", c.EvictMinIdle, 0, 24*time.Hour),
	)
}

// ErrNoCapacity means no node can take the instance.
var ErrNoCapacity = errors.New("insufficient capacity: no ready node has enough unreserved memory and CPU for this app")

// Node is a placement candidate with its capacity for apps and what is
// already reserved on it.
type Node struct {
	ID      uuid.UUID
	Name    string
	Address string
	// Capacity for apps (total minus the per-node reserve).
	MemoryMB   int64
	Millicores int64
	// Reserved by instances already placed.
	ReservedMemoryMB   int64
	ReservedMillicores int64
	Instances          int32
}

// fits reports whether n can take req, and the memory left after it.
func (n *Node) fits(req Request) (int64, bool) {
	freeMem := n.MemoryMB - n.ReservedMemoryMB
	freeCPU := n.Millicores - n.ReservedMillicores
	if req.MemoryMB > freeMem || req.Millicores > freeCPU {
		return 0, false
	}
	return freeMem - req.MemoryMB, true
}

// Request is what an instance reserves.
type Request struct {
	MemoryMB   int64
	Millicores int64
}

// Pick returns the best-fit node for req: the one with the least memory
// left after placement; ties go to fewer instances, then to the name (so
// the choice is deterministic). It reports false if nothing fits.
func Pick(nodes []Node, req Request) (Node, bool) {
	type option struct {
		node *Node
		left int64
	}
	var opts []option
	for i := range nodes {
		if left, ok := nodes[i].fits(req); ok {
			opts = append(opts, option{&nodes[i], left})
		}
	}
	if len(opts) == 0 {
		return Node{}, false
	}
	best := slices.MinFunc(opts, func(a, b option) int {
		return cmp.Or(cmp.Compare(a.left, b.left), cmp.Compare(a.node.Instances, b.node.Instances), cmp.Compare(a.node.Name, b.node.Name))
	})
	return *best.node, true
}

// Evictable is a running instance whose app may be put to sleep to make
// room, with the time it was last used.
type Evictable struct {
	InstanceID uuid.UUID
	AppID      uuid.UUID
	NodeID     uuid.UUID
	MemoryMB   int64
	Millicores int64
	LastActive time.Time
}

// ChooseEviction picks, on a single node, the least recently used
// candidates idle for at least minIdle whose release makes req fit there.
// Among nodes where that works it prefers the fewest evictions, then the
// set whose most recently used member was used least recently, then the
// node name. It reports false if no node can be freed enough.
func ChooseEviction(nodes []Node, cands []Evictable, req Request, now time.Time, minIdle time.Duration) (Node, []Evictable, bool) {
	byNode := map[uuid.UUID][]Evictable{}
	for _, c := range cands {
		if now.Sub(c.LastActive) >= minIdle {
			byNode[c.NodeID] = append(byNode[c.NodeID], c)
		}
	}
	type option struct {
		node    Node
		victims []Evictable
	}
	var opts []option
	for _, n := range nodes {
		list := byNode[n.ID]
		slices.SortFunc(list, func(a, b Evictable) int {
			return cmp.Or(a.LastActive.Compare(b.LastActive), cmp.Compare(a.InstanceID.String(), b.InstanceID.String()))
		})
		freed := n
		for i, c := range list {
			freed.ReservedMemoryMB -= c.MemoryMB
			freed.ReservedMillicores -= c.Millicores
			if _, ok := freed.fits(req); ok {
				opts = append(opts, option{node: n, victims: list[:i+1]})
				break
			}
		}
	}
	if len(opts) == 0 {
		return Node{}, nil, false
	}
	best := slices.MinFunc(opts, func(a, b option) int {
		newestA, newestB := a.victims[len(a.victims)-1].LastActive, b.victims[len(b.victims)-1].LastActive
		return cmp.Or(cmp.Compare(len(a.victims), len(b.victims)), newestA.Compare(newestB), cmp.Compare(a.node.Name, b.node.Name))
	})
	return best.node, best.victims, true
}

// Placement describes the instance to create.
type Placement struct {
	AppID        uuid.UUID
	DeploymentID uuid.UUID
	WorkspaceID  uuid.UUID
	MemoryMB     int32
	Millicores   int32
	// Cause is why the instance is needed (release, restart, wake,
	// failover, drain) and CauseAt when that happened.
	Cause   string
	CauseAt *time.Time
	// Resume, if set, is a sleeping instance of the app to start again on
	// its own node when that node has room (its container and image are
	// there).
	Resume *store.AppInstance
	// Evict, if set, lets the placement put idle apps to sleep when no
	// node has room.
	Evict *Eviction
}

// Eviction is what a placement needs to evict: when each app was last
// used (activity from the gateways) and the time now.
type Eviction struct {
	Activity map[uuid.UUID]time.Time
	Now      time.Time
}

// Evicted is an app put to sleep to make room.
type Evicted struct {
	App      store.App
	Instance store.AppInstance
	// LastActive is when it was last used.
	LastActive time.Time
}

// Result is a placement's outcome.
type Result struct {
	Instance store.AppInstance
	// Resumed reports that Placement.Resume was started again in place.
	Resumed bool
	// Evicted lists the apps put to sleep for this placement; the caller
	// stops their containers (keeping them) after committing.
	Evicted []Evicted
}

// Place locks the schedulable nodes, picks one and records the instance on
// it, all within q's transaction (the caller commits). It returns
// ErrNoCapacity if no node fits (after evicting, if allowed).
func Place(ctx context.Context, q *store.Queries, cfg *Config, p *Placement) (Result, error) {
	nodes, err := lockNodes(ctx, q, cfg)
	if err != nil {
		return Result{}, err
	}
	req := Request{MemoryMB: int64(p.MemoryMB), Millicores: int64(p.Millicores)}
	if p.Resume != nil && p.Resume.NodeID != nil {
		for i := range nodes {
			if nodes[i].ID != *p.Resume.NodeID {
				continue
			}
			if _, ok := nodes[i].fits(req); ok {
				inst, err := q.ResumeInstance(ctx, store.ResumeInstanceParams{ID: p.Resume.ID, Cause: p.Cause, CauseAt: p.CauseAt})
				if err != nil {
					return Result{}, fmt.Errorf("resume instance: %w", err)
				}
				return Result{Instance: inst, Resumed: true}, nil
			}
		}
	}
	if node, ok := Pick(nodes, req); ok {
		inst, err := createOn(ctx, q, &node, p)
		return Result{Instance: inst}, err
	}
	if p.Evict == nil {
		return Result{}, ErrNoCapacity
	}
	return evictAndPlace(ctx, q, cfg, p, nodes, req)
}

// lockNodes locks the schedulable nodes and returns them with what is
// reserved on each.
func lockNodes(ctx context.Context, q *store.Queries, cfg *Config) ([]Node, error) {
	rows, err := q.LockSchedulableNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("lock nodes: %w", err)
	}
	res, err := q.NodeReservations(ctx)
	if err != nil {
		return nil, fmt.Errorf("read reservations: %w", err)
	}
	reserved := make(map[uuid.UUID]store.NodeReservationsRow, len(res))
	for _, r := range res {
		if r.NodeID != nil {
			reserved[*r.NodeID] = r
		}
	}
	nodes := make([]Node, 0, len(rows))
	for _, r := range rows {
		n := Node{
			ID: r.ID, Name: r.Name, Address: r.AdvertiseAddress,
			MemoryMB:   r.MemoryTotalBytes>>20 - cfg.ReservedMemoryMB,
			Millicores: int64(r.CpuCount)*1000 - cfg.ReservedMillicores,
		}
		if rv, ok := reserved[r.ID]; ok {
			n.ReservedMemoryMB, n.ReservedMillicores, n.Instances = rv.MemoryMb, rv.CpuMillicores, rv.Instances
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

func createOn(ctx context.Context, q *store.Queries, node *Node, p *Placement) (store.AppInstance, error) {
	inst, err := q.CreateInstance(ctx, store.CreateInstanceParams{
		AppID: p.AppID, DeploymentID: p.DeploymentID, WorkspaceID: p.WorkspaceID, NodeID: &node.ID, NodeName: node.Name,
		MemoryMb: p.MemoryMB, CpuMillicores: p.Millicores, Address: node.Address,
	})
	if err != nil {
		return store.AppInstance{}, fmt.Errorf("record instance: %w", err)
	}
	cause := p.Cause
	if cause == "" {
		cause = CauseRelease
	}
	if cause != CauseRelease || p.CauseAt != nil {
		if err := q.SetInstanceCause(ctx, store.SetInstanceCauseParams{ID: inst.ID, Cause: cause, CauseAt: p.CauseAt}); err != nil {
			return store.AppInstance{}, fmt.Errorf("record instance cause: %w", err)
		}
		inst.Cause, inst.CauseAt = cause, p.CauseAt
	}
	return inst, nil
}

// evictAndPlace puts the least recently used idle apps of one node to
// sleep, within the transaction, and places the instance there.
func evictAndPlace(ctx context.Context, q *store.Queries, cfg *Config, p *Placement, nodes []Node, req Request) (Result, error) {
	rows, err := q.ListEvictable(ctx, p.AppID)
	if err != nil {
		return Result{}, fmt.Errorf("list evictable apps: %w", err)
	}
	cands := make([]Evictable, 0, len(rows))
	for _, r := range rows {
		if r.NodeID == nil {
			continue
		}
		last := p.Evict.Activity[r.AppID]
		for _, t := range []*time.Time{r.LastRequestAt, r.LastHealthyAt} {
			if t != nil && t.After(last) {
				last = *t
			}
		}
		cands = append(cands, Evictable{
			InstanceID: r.InstanceID, AppID: r.AppID, NodeID: *r.NodeID,
			MemoryMB: int64(r.MemoryMb), Millicores: int64(r.CpuMillicores), LastActive: last,
		})
	}
	node, victims, ok := ChooseEviction(nodes, cands, req, p.Evict.Now, cfg.EvictMinIdle)
	if !ok {
		return Result{}, ErrNoCapacity
	}
	deps := map[uuid.UUID]uuid.UUID{}
	for _, r := range rows {
		deps[r.InstanceID] = r.DeploymentID
	}
	out := Result{}
	for _, v := range victims {
		last := v.LastActive
		app, sleepErr := q.SleepApp(ctx, store.SleepAppParams{ID: v.AppID, Reason: SleepEvicted, LastRequestAt: &last, DeploymentID: ptr(deps[v.InstanceID])})
		if sleepErr != nil {
			// Changed under us (woken, stopped): the freed capacity is not
			// certain any more; this placement fails and is retried.
			return Result{}, fmt.Errorf("%w (an app chosen for eviction changed)", ErrNoCapacity)
		}
		inst, sleepErr := q.SleepInstance(ctx, store.SleepInstanceParams{ID: v.InstanceID, StopReason: SleepEvicted})
		if sleepErr != nil {
			return Result{}, fmt.Errorf("%w (an instance chosen for eviction changed)", ErrNoCapacity)
		}
		out.Evicted = append(out.Evicted, Evicted{App: app, Instance: inst, LastActive: last})
	}
	if out.Instance, err = createOn(ctx, q, &node, p); err != nil {
		return Result{}, err
	}
	return out, nil
}

// Instance causes and sleep reasons (the database's values).
const (
	CauseRelease  = "release"
	CauseRestart  = "restart"
	CauseWake     = "wake"
	CauseFailover = "failover"
	CauseDrain    = "drain"
	SleepIdle     = "idle"
	SleepEvicted  = "evicted"
)

func ptr[T any](v T) *T { return &v }
