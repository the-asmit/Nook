// Package activity records when apps last received requests, in Redis,
// cheaply enough for every request.
//
// Gateways touch an app in memory on every request and flush the latest
// time per app every few seconds in one ZADD with GT (a member's score
// only ever moves forward), so the number of Redis writes depends on the
// number of active apps per flush interval, not on traffic, and gateways
// flushing out of order cannot move an app's time back. The control
// plane reads the times to decide which apps are idle (sleep) and which
// were used least recently (eviction).
package activity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"
)

// Key is the sorted set of app IDs scored by last request (Unix ms).
const Key = "nook:apps:activity"

// Recorder batches request times on a gateway.
type Recorder struct {
	redis  *goredis.Client
	logger *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	pending map[uuid.UUID]time.Time
}

// NewRecorder returns a recorder writing to rdb.
func NewRecorder(rdb *goredis.Client, logger *slog.Logger) *Recorder {
	return &Recorder{redis: rdb, logger: logger, now: time.Now, pending: map[uuid.UUID]time.Time{}}
}

// Touch notes a request for app (in memory).
func (r *Recorder) Touch(app uuid.UUID) {
	now := r.now()
	r.mu.Lock()
	r.pending[app] = now
	r.mu.Unlock()
}

// Flush writes the pending times in one command. On failure they are kept
// for the next flush (unless newer touches replaced them).
func (r *Recorder) Flush(ctx context.Context) error {
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return nil
	}
	batch := r.pending
	r.pending = make(map[uuid.UUID]time.Time, len(batch))
	r.mu.Unlock()

	members := make([]goredis.Z, 0, len(batch))
	for app, t := range batch {
		members = append(members, goredis.Z{Score: float64(t.UnixMilli()), Member: app.String()})
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.redis.ZAddArgs(ctx, Key, goredis.ZAddArgs{GT: true, Members: members}).Err(); err != nil {
		r.mu.Lock()
		for app, t := range batch {
			if cur, ok := r.pending[app]; !ok || cur.Before(t) {
				r.pending[app] = t
			}
		}
		r.mu.Unlock()
		return fmt.Errorf("record app activity: %w", err)
	}
	return nil
}

// Run flushes every interval until ctx ends, then once more.
func (r *Recorder) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := r.Flush(context.WithoutCancel(ctx)); err != nil {
				r.logger.Warn("final activity flush failed", "error", err.Error())
			}
			return
		case <-t.C:
			if err := r.Flush(ctx); err != nil && ctx.Err() == nil {
				r.logger.WarnContext(ctx, "activity flush failed; retrying at the next interval", "error", err.Error())
			}
		}
	}
}

// Read returns the last request time of every app that had one.
func Read(ctx context.Context, rdb *goredis.Client) (map[uuid.UUID]time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	list, err := rdb.ZRangeWithScores(ctx, Key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("read app activity: %w", err)
	}
	out := make(map[uuid.UUID]time.Time, len(list))
	for _, z := range list {
		member, _ := z.Member.(string)
		id, err := uuid.Parse(member)
		if err != nil {
			continue
		}
		out[id] = time.UnixMilli(int64(z.Score))
	}
	return out, nil
}

// Forget removes deleted apps' entries.
func Forget(ctx context.Context, rdb *goredis.Client, apps ...uuid.UUID) error {
	if len(apps) == 0 {
		return nil
	}
	members := make([]any, len(apps))
	for i, a := range apps {
		members[i] = a.String()
	}
	if err := rdb.ZRem(ctx, Key, members...).Err(); err != nil {
		return fmt.Errorf("forget app activity: %w", err)
	}
	return nil
}

// Latest returns the later of t and the activity time of app in m.
func Latest(m map[uuid.UUID]time.Time, app uuid.UUID, ts ...*time.Time) time.Time {
	var out time.Time
	if a, ok := m[app]; ok {
		out = a
	}
	for _, t := range ts {
		if t != nil && t.After(out) {
			out = *t
		}
	}
	return out
}

// Last returns when app last received a request (nil if never recorded).
func Last(ctx context.Context, rdb *goredis.Client, app uuid.UUID) (*time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	score, err := rdb.ZScore(ctx, Key, app.String()).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read app activity: %w", err)
	}
	t := time.UnixMilli(int64(score))
	return &t, nil
}
