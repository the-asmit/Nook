//go:build integration

package nodes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/postgres"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/testinfra"
	"github.com/the-asmit/nook/migrations"
)

// manualClock is the injectable clock: tests move time explicitly.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now(context.Context) (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t, nil
}

func (c *manualClock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

type fixture struct {
	pool     *pgxpool.Pool
	redis    *goredis.Client
	clock    *manualClock
	registry *Registry
	detector *Detector
	admin    audit.Actor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	_, pgURL := testinfra.PostgresT(t)
	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err = postgres.Migrate(ctx, pool, migrations.FS, quiet); err != nil {
		t.Fatal(err)
	}
	_, redisURL := testinfra.RedisT(t)
	opts, err := goredis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	rdb := goredis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })

	ca, _, err := pki.LoadOrCreateCA(filepath.Join(t.TempDir(), "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	clock := &manualClock{t: time.Now()}
	hb, pub := NewHeartbeats(rdb, clock), NewPublisher(rdb)
	st := store.NewStore(pool)
	det, err := NewDetector(hb, pub, clock, cfg, prometheus.NewRegistry(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	var adminID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO users (email, oidc_issuer, oidc_subject, is_instance_admin)
		VALUES ('root@nook.test', 'https://idp.test', 'root', true) RETURNING id`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	return &fixture{pool: pool, redis: rdb, clock: clock, registry: NewRegistry(st, ca, hb, pub, cfg, quiet),
		detector: det, admin: audit.Actor{UserID: adminID}}
}

func (f *fixture) join(t *testing.T, name string) store.Node {
	t.Helper()
	ctx := context.Background()
	token, _, err := f.registry.CreateJoinToken(ctx, f.admin, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	joined, err := f.registry.Join(ctx, &JoinRequest{Token: token, CSR: csr, Name: name, Info: Info{Hostname: name}})
	if err != nil {
		t.Fatal(err)
	}
	return joined.Node
}

func (f *fixture) status(t *testing.T, id uuid.UUID) store.NodeStatus {
	t.Helper()
	var s store.NodeStatus
	if err := f.pool.QueryRow(context.Background(), "SELECT status FROM nodes WHERE id = $1", id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fixture) tickAt(t *testing.T, at time.Time) {
	t.Helper()
	f.clock.set(at)
	if err := f.detector.Tick(context.Background(), f.pool); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) heartbeatAt(t *testing.T, id uuid.UUID, at time.Time) {
	t.Helper()
	f.clock.set(at)
	if err := f.registry.RecordHeartbeat(context.Background(), id, &Sample{MemoryAvailableBytes: 1 << 30, DockerReachable: true}); err != nil {
		t.Fatal(err)
	}
}

func TestFailureDetectionTransitions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	sub := f.redis.Subscribe(ctx, EventsChannel)
	t.Cleanup(func() { _ = sub.Close() })
	if _, err := sub.Receive(ctx); err != nil {
		t.Fatal(err)
	}
	node := f.join(t, "n1")
	t0 := f.clock.t

	steps := []struct {
		heartbeat bool
		at        time.Duration
		want      store.NodeStatus
	}{
		{false, time.Second, store.NodeStatusJoining},  // joined, no heartbeat yet
		{true, 2 * time.Second, store.NodeStatusReady}, // first heartbeat at 2s
		{false, 2*time.Second + 15*time.Second - time.Millisecond, store.NodeStatusReady},
		{false, 2*time.Second + 15*time.Second, store.NodeStatusSuspect}, // 3 intervals missed
		{false, 2*time.Second + 30*time.Second - time.Millisecond, store.NodeStatusSuspect},
		{false, 2*time.Second + 30*time.Second, store.NodeStatusDead}, // dead threshold
		{true, time.Minute, store.NodeStatusReady},                    // heartbeats resume
	}
	for i, s := range steps {
		if s.heartbeat {
			f.heartbeatAt(t, node.ID, t0.Add(s.at))
		}
		f.tickAt(t, t0.Add(s.at))
		if got := f.status(t, node.ID); got != s.want {
			t.Fatalf("step %d (t+%s): status %s, want %s", i, s.at, got, s.want)
		}
	}

	rows, err := f.pool.Query(ctx, "SELECT coalesce(from_status::text, ''), to_status::text FROM node_events WHERE node_id = $1 ORDER BY id", node.ID)
	if err != nil {
		t.Fatal(err)
	}
	var history []string
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			t.Fatal(err)
		}
		history = append(history, from+"->"+to)
	}
	want := []string{"->joining", "joining->ready", "ready->suspect", "suspect->dead", "dead->ready"}
	if !slices.Equal(history, want) {
		t.Fatalf("node_events = %v, want %v", history, want)
	}

	// Every transition was also published.
	var published []string
	ch := sub.Channel()
	for len(published) < len(want) {
		select {
		case msg := <-ch:
			var ev Event
			if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
				t.Fatal(err)
			}
			from := ""
			if ev.FromStatus != nil {
				from = string(*ev.FromStatus)
			}
			published = append(published, fmt.Sprintf("%s->%s", from, ev.ToStatus))
		case <-time.After(5 * time.Second):
			t.Fatalf("published only %v", published)
		}
	}
	if !slices.Equal(published, want) {
		t.Fatalf("published %v, want %v", published, want)
	}

	// The heartbeat time was persisted along with the transitions.
	var last *time.Time
	if err := f.pool.QueryRow(ctx, "SELECT last_heartbeat_at FROM nodes WHERE id = $1", node.ID).Scan(&last); err != nil || last == nil {
		t.Fatalf("last_heartbeat_at not persisted: %v", err)
	}
}

func TestNeverConnectedNodeGoesDead(t *testing.T) {
	f := newFixture(t)
	node := f.join(t, "n2")
	f.tickAt(t, f.clock.t.Add(29*time.Second))
	if got := f.status(t, node.ID); got != store.NodeStatusJoining {
		t.Fatalf("status %s", got)
	}
	f.tickAt(t, f.clock.t.Add(2*time.Second))
	if got := f.status(t, node.ID); got != store.NodeStatusDead {
		t.Fatalf("status %s, want dead", got)
	}
}

func TestDrainingSurvivesHealthTransitions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	node := f.join(t, "n3")
	t0 := f.clock.t
	f.heartbeatAt(t, node.ID, t0)
	f.tickAt(t, t0)
	if _, err := f.registry.SetDraining(ctx, f.admin, "n3", true); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, node.ID); got != store.NodeStatusDraining {
		t.Fatalf("after drain: %s", got)
	}
	f.tickAt(t, t0.Add(time.Minute))
	if got := f.status(t, node.ID); got != store.NodeStatusDead {
		t.Fatalf("draining node without heartbeats: %s, want dead", got)
	}
	f.heartbeatAt(t, node.ID, t0.Add(2*time.Minute))
	f.tickAt(t, t0.Add(2*time.Minute))
	if got := f.status(t, node.ID); got != store.NodeStatusDraining {
		t.Fatalf("recovered draining node: %s, want draining", got)
	}
	if _, err := f.registry.SetDraining(ctx, f.admin, "n3", false); err != nil {
		t.Fatal(err)
	}
	if got := f.status(t, node.ID); got != store.NodeStatusReady {
		t.Fatalf("after undrain: %s", got)
	}
}

func TestNodeEventsAreAppendOnly(t *testing.T) {
	f := newFixture(t)
	f.join(t, "n4")
	for _, stmt := range []string{"UPDATE node_events SET reason = 'x'", "DELETE FROM node_events", "TRUNCATE node_events"} {
		if _, err := f.pool.Exec(context.Background(), stmt); err == nil {
			t.Errorf("%q succeeded", stmt)
		}
	}
}

func TestHeartbeatPersistenceIsThrottled(t *testing.T) {
	f := newFixture(t)
	node := f.join(t, "n5")
	t0 := f.clock.t
	read := func() time.Time {
		var v *time.Time
		if err := f.pool.QueryRow(context.Background(), "SELECT last_heartbeat_at FROM nodes WHERE id = $1", node.ID).Scan(&v); err != nil || v == nil {
			t.Fatalf("read: %v", err)
		}
		return *v
	}
	f.heartbeatAt(t, node.ID, t0)
	first := read()
	f.heartbeatAt(t, node.ID, t0.Add(10*time.Second))
	if !read().Equal(first) {
		t.Fatal("persisted again before the persist interval")
	}
	f.heartbeatAt(t, node.ID, t0.Add(31*time.Second))
	if read().Equal(first) {
		t.Fatal("not persisted after the persist interval")
	}
	seen, err := f.registry.heartbeats.LastSeen(context.Background(), []uuid.UUID{node.ID})
	if err != nil || !seen[node.ID].Equal(t0.Add(31*time.Second).Truncate(time.Millisecond)) {
		t.Fatalf("redis last seen %v %v", seen, err)
	}
}
