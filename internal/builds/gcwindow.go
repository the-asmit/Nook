package builds

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/store"
)

// The registry's garbage collector deletes blobs no manifest references.
// A push in progress has uploaded blobs that no manifest references yet,
// so GC must never overlap a push. Before it runs, the GC job opens a
// maintenance window: while the window is open no build starts, and the
// window only opens once no build is running.

const (
	gcWindowKey = "nook:registry:gc-window"
	// MaxGCWindow bounds a window, so a GC job that dies cannot stop
	// builds for long.
	MaxGCWindow = 30 * time.Minute
)

func gcWindowActive(ctx context.Context, rdb *goredis.Client) (bool, error) {
	n, err := rdb.Exists(ctx, gcWindowKey).Result()
	if err != nil {
		return false, fmt.Errorf("check registry maintenance window: %w", err)
	}
	return n == 1, nil
}

// GCWindow opens and closes registry maintenance windows.
type GCWindow struct {
	store *store.Store
	redis *goredis.Client
	// poll and wait bound how long Open waits for running builds.
	poll time.Duration
	wait time.Duration
}

// NewGCWindow returns the window coordinator.
func NewGCWindow(st *store.Store, rdb *goredis.Client) *GCWindow {
	return &GCWindow{store: st, redis: rdb, poll: time.Second, wait: time.Minute}
}

// Open starts a window of length ttl once no build is running. If builds
// keep running for the wait period it gives up (409): the GC job tries
// again later.
func (g *GCWindow) Open(ctx context.Context, ttl time.Duration) error {
	ttl = min(max(ttl, time.Minute), MaxGCWindow)
	ok, err := g.redis.SetNX(ctx, gcWindowKey, time.Now().UTC().Format(time.RFC3339), ttl).Result()
	if err != nil {
		return fmt.Errorf("open maintenance window: %w", err)
	}
	if !ok {
		return apperr.Conflict("window_open", "a registry maintenance window is already open")
	}
	deadline := time.Now().Add(g.wait)
	for {
		n, err := g.store.CountActiveBuilds(ctx)
		if err != nil {
			g.Close(context.WithoutCancel(ctx))
			return fmt.Errorf("count active builds: %w", err)
		}
		if n == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			g.Close(context.WithoutCancel(ctx))
			return apperr.Conflict("builds_running", "%d builds are running; try again later", n)
		}
		if !sleep(ctx, g.poll) {
			g.Close(context.WithoutCancel(ctx))
			return errors.Join(ctx.Err(), errors.New("maintenance window not opened"))
		}
	}
}

// Close ends the window; builds resume.
func (g *GCWindow) Close(ctx context.Context) {
	_ = g.redis.Del(ctx, gcWindowKey).Err()
}
