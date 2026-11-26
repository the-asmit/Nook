//go:build integration

package activity

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"

	"github.com/the-asmit/nook/internal/testinfra"
)

var rdb *goredis.Client

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	c, url, err := testinfra.StartRedis(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(c) }()
	opts, err := goredis.ParseURL(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	rdb = goredis.NewClient(opts)
	defer func() { _ = rdb.Close() }()
	return m.Run()
}

// TestActivityIsBatchedAndMonotonic: touches stay in memory until a flush
// writes the latest time per app in one command; a gateway flushing an
// older time later cannot move an app's activity back.
func TestActivityIsBatchedAndMonotonic(t *testing.T) {
	ctx := t.Context()
	if err := rdb.Del(ctx, Key).Err(); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t0 := time.UnixMilli(1_700_000_000_000)
	newer, older := NewRecorder(rdb, logger), NewRecorder(rdb, logger)
	newer.now = func() time.Time { return t0.Add(time.Minute) }
	older.now = func() time.Time { return t0 }

	a, b := uuid.NewV7(), uuid.NewV7()
	for range 1000 {
		newer.Touch(a)
	}
	older.Touch(a)
	older.Touch(b)
	if got, err := Read(ctx, rdb); err != nil || len(got) != 0 {
		t.Fatalf("touches reached Redis before a flush: %v %v", got, err)
	}
	if err := newer.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := older.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := Read(ctx, rdb)
	if err != nil {
		t.Fatal(err)
	}
	if !got[a].Equal(t0.Add(time.Minute)) || !got[b].Equal(t0) {
		t.Fatalf("activity = %v; want a at t0+1m (not moved back), b at t0", got)
	}
	if last, err := Last(ctx, rdb, a); err != nil || last == nil || !last.Equal(t0.Add(time.Minute)) {
		t.Fatalf("Last(a) = %v, %v", last, err)
	}
	if last, err := Last(ctx, rdb, uuid.NewV7()); err != nil || last != nil {
		t.Fatalf("Last(unknown) = %v, %v", last, err)
	}
	if err := newer.Flush(ctx); err != nil { // nothing pending: no write
		t.Fatal(err)
	}
	if err := Forget(ctx, rdb, a, b); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(ctx, rdb); err != nil || len(got) != 0 {
		t.Fatalf("after Forget: %v %v", got, err)
	}
	if !Latest(map[uuid.UUID]time.Time{a: t0}, a, nil, ptr(t0.Add(time.Second))).Equal(t0.Add(time.Second)) {
		t.Fatal("Latest")
	}
}

// TestFailedFlushKeepsTouches: a flush that cannot reach Redis keeps the
// times for the next one.
func TestFailedFlushKeepsTouches(t *testing.T) {
	ctx := t.Context()
	if err := rdb.Del(ctx, Key).Err(); err != nil {
		t.Fatal(err)
	}
	broken := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, MaxRetries: -1})
	defer func() { _ = broken.Close() }()
	r := NewRecorder(broken, slog.New(slog.NewTextHandler(io.Discard, nil)))
	app := uuid.NewV7()
	r.Touch(app)
	if err := r.Flush(ctx); err == nil {
		t.Fatal("a flush to an unreachable Redis succeeded")
	}
	r.redis = rdb
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(ctx, rdb); err != nil || got[app].IsZero() {
		t.Fatalf("the touch was lost: %v %v", got, err)
	}
}

func ptr[T any](v T) *T { return &v }
