//go:build integration

package postgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/testcontainers/testcontainers-go"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/testinfra"
	"github.com/the-asmit/nook/migrations"
)

// adminURL points at the container shared by this package's tests; each
// test creates its own database on it.
var adminURL string

func TestMain(m *testing.M) {
	os.Exit(runWithPostgres(m))
}

func runWithPostgres(m *testing.M) int {
	c, connURL, err := testinfra.StartPostgres(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(c) }()
	adminURL = connURL
	return m.Run()
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func newTestPool(t *testing.T, connURL string) *pgxpool.Pool {
	t.Helper()
	cfg := Config{
		URL: config.NewSecret(connURL), MaxConns: 10, MinConns: 0,
		MaxConnLifetime: time.Hour, MaxConnIdleTime: time.Minute,
		HealthCheckPeriod: time.Minute, ConnectTimeout: 5 * time.Second,
	}
	pool, err := NewPool(context.Background(), &cfg, "nook-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func installedExtensions(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var names string
	err := pool.QueryRow(testCtx(t, 10*time.Second),
		"SELECT coalesce(string_agg(extname, ',' ORDER BY extname), '') FROM pg_extension WHERE extname IN ('citext', 'pgcrypto')").Scan(&names)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func appliedVersions(t *testing.T, pool *pgxpool.Pool) []int64 {
	t.Helper()
	rows, err := pool.Query(testCtx(t, 10*time.Second),
		"SELECT version_id FROM goose_db_version WHERE is_applied AND version_id > 0 ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMigrateAppliesExtensionsAndIsIdempotent(t *testing.T) {
	pool := newTestPool(t, testinfra.CreateDatabase(t, adminURL))
	ctx := testCtx(t, time.Minute)

	if err := Migrate(ctx, pool, migrations.FS, quiet); err != nil {
		t.Fatalf("first Migrate() = %v", err)
	}
	if got := installedExtensions(t, pool); got != "citext,pgcrypto" {
		t.Fatalf("extensions = %q", got)
	}
	if err := Migrate(ctx, pool, migrations.FS, quiet); err != nil {
		t.Fatalf("second Migrate() = %v", err)
	}
	if got := appliedVersions(t, pool); len(got) != 1 || got[0] != 1 {
		t.Fatalf("applied versions = %v, want [1] exactly once", got)
	}
}

func TestMigrationsAreReversible(t *testing.T) {
	pool := newTestPool(t, testinfra.CreateDatabase(t, adminURL))
	ctx := testCtx(t, time.Minute)
	if err := Migrate(ctx, pool, migrations.FS, quiet); err != nil {
		t.Fatal(err)
	}

	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, 0); err != nil {
		t.Fatalf("DownTo(0) = %v", err)
	}
	if got := installedExtensions(t, pool); got != "" {
		t.Fatalf("extensions after down = %q, want none", got)
	}
	if err := Migrate(ctx, pool, migrations.FS, quiet); err != nil {
		t.Fatalf("re-apply after down: %v", err)
	}
	if got := installedExtensions(t, pool); got != "citext,pgcrypto" {
		t.Fatalf("extensions after re-apply = %q", got)
	}
}

// TestConcurrentMigratorsDoNotConflict simulates several server instances
// starting at once against an empty database. Without the advisory lock
// they race on creating goose's version table and the extensions.
func TestConcurrentMigratorsDoNotConflict(t *testing.T) {
	connURL := testinfra.CreateDatabase(t, adminURL)
	const instances = 4
	pools := make([]*pgxpool.Pool, instances)
	for i := range pools {
		pools[i] = newTestPool(t, connURL) // separate pools, like separate processes
	}
	ctx := testCtx(t, 2*time.Minute)

	start := make(chan struct{})
	errs := make(chan error, instances)
	for _, p := range pools {
		go func() {
			<-start
			errs <- Migrate(ctx, p, migrations.FS, quiet)
		}()
	}
	close(start)
	for range instances {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Migrate() = %v", err)
		}
	}
	if got := appliedVersions(t, pools[0]); len(got) != 1 || got[0] != 1 {
		t.Fatalf("applied versions = %v, want [1] exactly once", got)
	}
	if got := installedExtensions(t, pools[0]); got != "citext,pgcrypto" {
		t.Fatalf("extensions = %q", got)
	}
}

// holdMigrationLock takes the advisory lock on a dedicated connection, as
// another instance mid-migration would, and returns a release function.
func holdMigrationLock(t *testing.T, pool *pgxpool.Pool) func() {
	t.Helper()
	db := stdlib.OpenDBFromPool(pool)
	conn, err := db.Conn(testCtx(t, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(testCtx(t, 10*time.Second), "SELECT pg_advisory_lock($1)", MigrationLockID); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		var ok bool
		if err := conn.QueryRowContext(testCtx(t, 10*time.Second), "SELECT pg_advisory_unlock($1)", MigrationLockID).Scan(&ok); err != nil || !ok {
			t.Errorf("release lock: ok=%v err=%v", ok, err)
		}
		_ = conn.Close()
		_ = db.Close()
	}
	t.Cleanup(release)
	return release
}

func waitingForAdvisoryLock(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	var waiting int
	err := pool.QueryRow(testCtx(t, 5*time.Second), `
		SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND NOT granted
		  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&waiting)
	if err != nil {
		t.Fatal(err)
	}
	return waiting > 0
}

func versionTableExists(t *testing.T, pool *pgxpool.Pool) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(testCtx(t, 5*time.Second), "SELECT to_regclass('goose_db_version') IS NOT NULL").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func TestMigrateWaitsForLockHolder(t *testing.T) {
	pool := newTestPool(t, testinfra.CreateDatabase(t, adminURL))
	release := holdMigrationLock(t, pool)

	done := make(chan error, 1)
	go func() { done <- Migrate(testCtx(t, time.Minute), pool, migrations.FS, quiet) }()

	deadline := time.Now().Add(30 * time.Second)
	for !waitingForAdvisoryLock(t, pool) {
		if time.Now().After(deadline) {
			t.Fatal("migrator never started waiting for the advisory lock")
		}
	}
	select {
	case err := <-done:
		t.Fatalf("Migrate() returned while the lock was held: %v", err)
	default:
	}
	if versionTableExists(t, pool) {
		t.Fatal("migrator touched the schema before acquiring the lock")
	}

	release()
	if err := <-done; err != nil {
		t.Fatalf("Migrate() after release = %v", err)
	}
	if got := appliedVersions(t, pool); len(got) != 1 {
		t.Fatalf("applied versions = %v", got)
	}
}

func TestMigrateGivesUpWhenLockIsNeverReleased(t *testing.T) {
	pool := newTestPool(t, testinfra.CreateDatabase(t, adminURL))
	holdMigrationLock(t, pool)

	err := Migrate(testCtx(t, 500*time.Millisecond), pool, migrations.FS, quiet)
	if err == nil || !strings.Contains(err.Error(), "migration lock") {
		t.Fatalf("Migrate() = %v, want a lock wait error", err)
	}
}

func TestLockIsReleasedAfterMigrating(t *testing.T) {
	pool := newTestPool(t, testinfra.CreateDatabase(t, adminURL))
	if err := Migrate(testCtx(t, time.Minute), pool, migrations.FS, quiet); err != nil {
		t.Fatal(err)
	}
	var acquired bool
	err := pool.QueryRow(testCtx(t, 5*time.Second),
		"SELECT pg_try_advisory_lock($1), pg_advisory_unlock($1)", MigrationLockID).Scan(&acquired, new(bool))
	if err != nil || !acquired {
		t.Fatalf("lock still held after Migrate returned: acquired=%v err=%v", acquired, err)
	}
}

func TestPoolCollectorExportsStats(t *testing.T) {
	pool := newTestPool(t, testinfra.CreateDatabase(t, adminURL))
	if err := pool.Ping(testCtx(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	if err := reg.Register(NewPoolCollector(pool)); err != nil {
		t.Fatal(err)
	}
	expected := `
# HELP nook_postgres_pool_max_conns Configured maximum pool size.
# TYPE nook_postgres_pool_max_conns gauge
nook_postgres_pool_max_conns 10
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "nook_postgres_pool_max_conns"); err != nil {
		t.Fatal(err)
	}
	if n, err := testutil.GatherAndCount(reg); err != nil || n != 9 {
		t.Fatalf("metric count = %d, err %v; want 9", n, err)
	}
}
