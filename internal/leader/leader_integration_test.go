//go:build integration

package leader

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/testinfra"
)

const interval = 200 * time.Millisecond

// takeoverBound is the documented worst case after a leader's session ends:
// the follower's next attempt (one interval) plus scheduling slack.
const takeoverBound = 2*interval + time.Second

type instance struct {
	e     *Elector
	ticks atomic.Int64 // leader work done (fenced through the session)
	stop  context.CancelFunc
	done  chan struct{}
}

func start(t *testing.T, cfg *pgx.ConnConfig) *instance {
	t.Helper()
	e, err := New("test_role", 0x7465737472, cfg, interval, prometheus.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	in := &instance{e: e, stop: cancel, done: make(chan struct{})}
	go func() {
		defer close(in.done)
		e.Run(ctx, func(ctx context.Context, s *Session) {
			for ctx.Err() == nil {
				// Work that must be fenced: it only counts if it ran on the
				// lock-holding session.
				if s.Do(ctx, func(c *pgx.Conn) error {
					_, err := c.Exec(ctx, "SELECT 1")
					return err
				}) == nil {
					in.ticks.Add(1)
				}
				wait(ctx, interval/4)
			}
		})
	}()
	t.Cleanup(func() { cancel(); <-in.done })
	return in
}

func eventually(t *testing.T, within time.Duration, cond func() bool, what string) time.Duration {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > within {
			t.Fatalf("%s did not happen within %s", what, within)
		}
		wait(context.Background(), 10*time.Millisecond)
	}
	return time.Since(start)
}

func TestExactlyOneLeaderAndFailover(t *testing.T) {
	_, url := testinfra.PostgresT(t)
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	a, b := start(t, cfg), start(t, cfg)
	eventually(t, 5*time.Second, func() bool { return a.e.IsLeader() != b.e.IsLeader() }, "a single leader")
	leaderInst, follower := a, b
	if b.e.IsLeader() {
		leaderInst, follower = b, a
	}
	// The follower must stay a follower while the leader is healthy.
	for range 10 {
		wait(context.Background(), interval)
		if follower.e.IsLeader() || !leaderInst.e.IsLeader() {
			t.Fatal("leadership changed while the leader was healthy")
		}
	}
	if follower.ticks.Load() != 0 {
		t.Fatal("the follower did leader work")
	}

	// Kill the leader's database session, as a crash or partition would.
	var pid int
	if err := pool.QueryRow(context.Background(),
		"SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	took := eventually(t, takeoverBound, follower.e.IsLeader, "takeover by the follower")
	eventually(t, takeoverBound, func() bool { return !leaderInst.e.IsLeader() }, "the old leader stepping down")
	t.Logf("takeover took %s (bound %s)", took, takeoverBound)

	before := follower.ticks.Load()
	eventually(t, 2*time.Second, func() bool { return follower.ticks.Load() > before }, "the new leader doing work")

	// The former leader rejoins as a follower.
	eventually(t, 5*time.Second, func() bool { return !leaderInst.e.IsLeader() && follower.e.IsLeader() }, "stable leadership")
}

func TestLeaderReleasesLockOnShutdown(t *testing.T) {
	_, url := testinfra.PostgresT(t)
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	a := start(t, cfg)
	eventually(t, 5*time.Second, a.e.IsLeader, "leadership")
	b := start(t, cfg)
	a.stop()
	<-a.done
	if a.e.IsLeader() {
		t.Fatal("stopped instance still reports leadership")
	}
	eventually(t, takeoverBound, b.e.IsLeader, "takeover after a clean shutdown")
}
