package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"
)

// Clock is the time source for heartbeats and failure detection. All
// control-plane instances must share one, so a heartbeat received by one
// instance is judged correctly by the leader on another.
type Clock interface {
	Now(ctx context.Context) (time.Time, error)
}

// RedisClock reads the time from the Redis server: one clock for every
// control-plane instance, immune to skew between their hosts and to the
// agents' clocks.
type RedisClock struct {
	Client *goredis.Client
}

// Now implements Clock.
func (c RedisClock) Now(ctx context.Context) (time.Time, error) {
	t, err := c.Client.Time(ctx).Result()
	if err != nil {
		return time.Time{}, fmt.Errorf("read redis time: %w", err)
	}
	return t, nil
}

// Redis keys. See docs/architecture.md for the full list.
const (
	// lastSeenKey is a sorted set: member = node ID, score = Unix
	// milliseconds of the latest heartbeat.
	lastSeenKey = "nook:nodes:last_seen"
	// sampleTTL keeps a node's latest heartbeat sample around long after
	// it went quiet, for `nook node inspect`.
	sampleTTL = 7 * 24 * time.Hour
)

func sampleKey(id uuid.UUID) string { return "nook:node:" + id.String() + ":heartbeat" }

// Sample is one heartbeat as stored, with the control plane's receive time.
type Sample struct {
	ReceivedAt           time.Time     `json:"received_at"`
	MemoryAvailableBytes int64         `json:"memory_available_bytes"`
	CPULoad1m            float64       `json:"cpu_load_1m"`
	DiskFreeBytes        int64         `json:"disk_free_bytes"`
	RunningContainers    int32         `json:"running_containers"`
	AgentVersion         string        `json:"agent_version"`
	Uptime               time.Duration `json:"uptime"`
	DockerReachable      bool          `json:"docker_reachable"`
	// BuildsUnavailableReason says why the node cannot build, or is empty.
	BuildsUnavailableReason string `json:"builds_unavailable_reason,omitempty"`
}

// Heartbeats stores the latest heartbeat of every node in Redis, where
// every control-plane instance (in particular the leader running the
// failure detector) can see it, whichever instance received it.
type Heartbeats struct {
	redis *goredis.Client
	clock Clock
}

// NewHeartbeats returns a heartbeat store.
func NewHeartbeats(client *goredis.Client, clock Clock) *Heartbeats {
	return &Heartbeats{redis: client, clock: clock}
}

// Record stamps s with the current (shared) time and stores it.
func (h *Heartbeats) Record(ctx context.Context, nodeID uuid.UUID, s *Sample) error {
	now, err := h.clock.Now(ctx)
	if err != nil {
		return err
	}
	s.ReceivedAt = now
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode heartbeat: %w", err)
	}
	_, err = h.redis.TxPipelined(ctx, func(p goredis.Pipeliner) error {
		p.ZAdd(ctx, lastSeenKey, goredis.Z{Score: float64(now.UnixMilli()), Member: nodeID.String()})
		p.Set(ctx, sampleKey(nodeID), data, sampleTTL)
		return nil
	})
	if err != nil {
		return fmt.Errorf("store heartbeat: %w", err)
	}
	return nil
}

// LastSeen returns the latest heartbeat time of each of ids that has one.
func (h *Heartbeats) LastSeen(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	out := make(map[uuid.UUID]time.Time, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	members := make([]string, len(ids))
	for i, id := range ids {
		members[i] = id.String()
	}
	scores, err := h.redis.ZMScore(ctx, lastSeenKey, members...).Result()
	if err != nil {
		return nil, fmt.Errorf("read heartbeats: %w", err)
	}
	// ZMSCORE answers one score per member, in order; missing members
	// score 0.
	for i, id := range ids {
		if i < len(scores) && scores[i] > 0 {
			out[id] = time.UnixMilli(int64(scores[i]))
		}
	}
	return out, nil
}

// Latest returns a node's most recent heartbeat sample, if any.
func (h *Heartbeats) Latest(ctx context.Context, nodeID uuid.UUID) (*Sample, error) {
	data, err := h.redis.Get(ctx, sampleKey(nodeID)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read heartbeat: %w", err)
	}
	var s Sample
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("decode heartbeat: %w", err)
	}
	return &s, nil
}

// Forget deletes a removed node's heartbeat data.
func (h *Heartbeats) Forget(ctx context.Context, nodeID uuid.UUID) error {
	_, err := h.redis.TxPipelined(ctx, func(p goredis.Pipeliner) error {
		p.ZRem(ctx, lastSeenKey, nodeID.String())
		p.Del(ctx, sampleKey(nodeID))
		return nil
	})
	if err != nil {
		return fmt.Errorf("forget heartbeat: %w", err)
	}
	return nil
}
