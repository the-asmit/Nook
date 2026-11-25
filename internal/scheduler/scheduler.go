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
package scheduler

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
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
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	return errors.Join(
		config.CheckRange("NOOK_SCHEDULER_NODE_RESERVED_MEMORY_MB", c.ReservedMemoryMB, 0, 1<<20),
		config.CheckRange("NOOK_SCHEDULER_NODE_RESERVED_MILLICORES", c.ReservedMillicores, 0, 1<<20),
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

// Placement describes the instance to create.
type Placement struct {
	AppID        uuid.UUID
	DeploymentID uuid.UUID
	WorkspaceID  uuid.UUID
	MemoryMB     int32
	Millicores   int32
}

// Place locks the schedulable nodes, picks one and records the instance on
// it, all within q's transaction (the caller commits). It returns
// ErrNoCapacity if no node fits.
func Place(ctx context.Context, q *store.Queries, cfg *Config, p *Placement) (store.AppInstance, error) {
	rows, err := q.LockSchedulableNodes(ctx)
	if err != nil {
		return store.AppInstance{}, fmt.Errorf("lock nodes: %w", err)
	}
	res, err := q.NodeReservations(ctx)
	if err != nil {
		return store.AppInstance{}, fmt.Errorf("read reservations: %w", err)
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
	node, ok := Pick(nodes, Request{MemoryMB: int64(p.MemoryMB), Millicores: int64(p.Millicores)})
	if !ok {
		return store.AppInstance{}, ErrNoCapacity
	}
	inst, err := q.CreateInstance(ctx, store.CreateInstanceParams{
		AppID: p.AppID, DeploymentID: p.DeploymentID, WorkspaceID: p.WorkspaceID, NodeID: &node.ID, NodeName: node.Name,
		MemoryMb: p.MemoryMB, CpuMillicores: p.Millicores, Address: node.Address,
	})
	if err != nil {
		return store.AppInstance{}, fmt.Errorf("record instance: %w", err)
	}
	return inst, nil
}
