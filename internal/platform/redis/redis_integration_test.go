//go:build integration

package redis

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/testinfra"
)

func TestClientAgainstRealRedis(t *testing.T) {
	_, connURL := testinfra.RedisT(t)
	client, err := NewClient(new(validConfig(connURL)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("Ping() = %v", err)
	}
	if err := client.Set(ctx, "k", "v", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := client.Get(ctx, "k").Result(); err != nil || got != "v" {
		t.Fatalf("Get() = %q, %v", got, err)
	}
}

// TestContextDeadlineIsHonored proves ContextTimeoutEnabled is in effect:
// a blocking command gives up at the caller's deadline instead of waiting
// for the much longer configured read timeout.
func TestContextDeadlineIsHonored(t *testing.T) {
	_, connURL := testinfra.RedisT(t)
	cfg := validConfig(connURL)
	cfg.ReadTimeout = time.Minute
	client, err := NewClient(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = client.BLPop(ctx, 0, "never-pushed").Err() // 0 = block forever server-side
	// go-redis applies the context deadline to the socket, so the error is
	// a network timeout rather than ctx.Err(); what matters is that the call
	// returned at the caller's deadline, not after the one-minute read timeout.
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("BLPop() = %v, want a timeout error", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("BLPop() took %s; the context deadline was ignored", elapsed)
	}
}
