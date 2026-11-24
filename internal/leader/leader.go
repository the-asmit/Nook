// Package leader elects one control-plane instance to run a singleton task
// (the failure detector) using a PostgreSQL session-level advisory lock
// held on a dedicated connection.
//
// Holding the lock *is* being the leader. The lock lives exactly as long as
// the database session: if the leader process dies or its connection is
// cut, Postgres releases the lock and a follower's next attempt wins.
package leader

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/platform/metrics"
)

// Elector competes for leadership of one role.
type Elector struct {
	role     string
	lockID   int64
	conn     *pgx.ConnConfig
	interval time.Duration
	logger   *slog.Logger
	gauge    prometheus.Gauge

	mu     sync.Mutex
	leader bool
}

// FailureDetectorLockID is the advisory lock key for the failure detector
// role ("nookfdet" in ASCII); distinct from the migration lock.
const FailureDetectorLockID int64 = 0x6e6f6f6b66646574

// New returns an elector for role. connConfig is copied and given TCP
// keepalive settings so that Postgres notices a vanished leader (say, a
// network partition) within seconds and releases its lock; interval is
// both how often a follower tries to take over and how often the leader
// verifies its lock connection. Takeover after a leader's connection ends
// therefore takes at most one interval; after a silent partition, at most
// the keepalive timeout (about 11 s) plus one interval.
func New(role string, lockID int64, connConfig *pgx.ConnConfig, interval time.Duration, reg prometheus.Registerer, logger *slog.Logger) (*Elector, error) {
	cfg := connConfig.Copy()
	cfg.RuntimeParams["application_name"] = "nook-leader-" + role
	cfg.RuntimeParams["tcp_keepalives_idle"] = "5"
	cfg.RuntimeParams["tcp_keepalives_interval"] = "2"
	cfg.RuntimeParams["tcp_keepalives_count"] = "3"
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metrics.Namespace, Name: "leader",
		Help:        "1 while this instance holds leadership for the role, else 0.",
		ConstLabels: prometheus.Labels{"role": role},
	})
	if err := reg.Register(gauge); err != nil {
		return nil, fmt.Errorf("register leader metric: %w", err)
	}
	return &Elector{role: role, lockID: lockID, conn: cfg, interval: interval, logger: logger, gauge: gauge}, nil
}

// IsLeader reports whether this instance currently leads.
func (e *Elector) IsLeader() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.leader
}

func (e *Elector) setLeader(v bool) {
	e.mu.Lock()
	e.leader = v
	e.mu.Unlock()
	if v {
		e.gauge.Set(1)
	} else {
		e.gauge.Set(0)
	}
}

// Session is the database session that holds the leader lock. Work that
// must only ever be done by the leader runs its queries through Do: if the
// session is gone (and with it the lock), those queries fail, so a former
// leader that has not noticed yet cannot write anything. This fencing is
// what makes "exactly one leader" hold for the data, not just the flag.
type Session struct {
	mu   sync.Mutex
	conn *pgx.Conn
}

// Do runs fn on the lock connection. pgx connections are not safe for
// concurrent use, so calls are serialized.
func (s *Session) Do(ctx context.Context, fn func(*pgx.Conn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("leader session: %w", err)
	}
	return fn(s.conn)
}

// Run competes for leadership until ctx is done. Whenever this instance
// becomes leader it calls lead with a context that is canceled the moment
// leadership is lost, and with the lock-holding Session; lead must return
// promptly when the context ends.
func (e *Elector) Run(ctx context.Context, lead func(context.Context, *Session)) {
	for ctx.Err() == nil {
		e.attempt(ctx, lead)
		if !wait(ctx, e.interval) {
			return
		}
	}
}

// attempt holds one database session: it tries to acquire the lock until
// it succeeds, then leads until the session fails or ctx ends.
func (e *Elector) attempt(ctx context.Context, lead func(context.Context, *Session)) {
	conn, err := e.connect(ctx)
	if err != nil {
		e.logger.WarnContext(ctx, "leader election: cannot reach postgres", "role", e.role, "error", err.Error())
		return
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.interval)
		defer cancel()
		_ = conn.Close(closeCtx) // Ending the session releases the lock.
	}()

	for {
		acquired, err := e.tryLock(ctx, conn)
		if err != nil {
			if ctx.Err() == nil {
				e.logger.WarnContext(ctx, "leader election: lock attempt failed", "role", e.role, "error", err.Error())
			}
			return
		}
		if acquired {
			break
		}
		if !wait(ctx, e.interval) {
			return
		}
	}

	e.setLeader(true)
	e.logger.InfoContext(ctx, "became leader", "role", e.role)
	sess := &Session{conn: conn}
	leadCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		lead(leadCtx, sess)
	}()

	reason := e.hold(ctx, sess)
	// Stop leading before anyone else can start: the lock is released only
	// when the deferred Close runs, after lead has returned.
	cancel()
	<-done
	e.setLeader(false)
	e.logger.InfoContext(ctx, "lost leadership", "role", e.role, "reason", reason)
}

// hold verifies the lock connection every interval until it fails or ctx
// ends, and returns why leadership ended.
func (e *Elector) hold(ctx context.Context, sess *Session) string {
	for {
		if !wait(ctx, e.interval) {
			return "shutting down"
		}
		pingCtx, cancel := context.WithTimeout(ctx, e.interval)
		err := sess.Do(pingCtx, func(c *pgx.Conn) error { return c.Ping(pingCtx) })
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return "shutting down"
			}
			return "lock connection failed: " + err.Error()
		}
	}
}

func (e *Elector) connect(ctx context.Context) (*pgx.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, max(e.interval, 5*time.Second))
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, e.conn)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return conn, nil
}

func (e *Elector) tryLock(ctx context.Context, conn *pgx.Conn) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, max(e.interval, 5*time.Second))
	defer cancel()
	var ok bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", e.lockID).Scan(&ok); err != nil {
		return false, fmt.Errorf("pg_try_advisory_lock: %w", err)
	}
	return ok, nil
}

// wait sleeps for d or until ctx is done, reporting whether to continue.
func wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
