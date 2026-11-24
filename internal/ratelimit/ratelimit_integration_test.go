//go:build integration

package ratelimit

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/testinfra"
)

func TestFixedWindowLimit(t *testing.T) {
	_, url := testinfra.RedisT(t)
	opts, parseErr := goredis.ParseURL(url)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	client := goredis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	l := New(client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rule := Rule{Name: "test", Limit: 3, Window: time.Hour}
	for i := range 3 {
		res, err := l.Allow(ctx, rule, "10.0.0.1")
		if err != nil || !res.Allowed {
			t.Fatalf("event %d: %+v %v", i, res, err)
		}
	}
	res, err := l.Allow(ctx, rule, "10.0.0.1")
	if err != nil || res.Allowed || res.RetryAfter <= 0 || res.RetryAfter > time.Hour {
		t.Fatalf("4th event: %+v %v", res, err)
	}
	// Other keys and other rules have their own counters.
	if res, _ := l.Allow(ctx, rule, "10.0.0.2"); !res.Allowed {
		t.Fatal("another key was limited")
	}
	if res, _ := l.Allow(ctx, Rule{Name: "other", Limit: 1, Window: time.Hour}, "10.0.0.1"); !res.Allowed {
		t.Fatal("another rule was limited")
	}
	// Every counter expires with its window.
	keys := client.Keys(ctx, keyPrefix+"*").Val()
	if len(keys) == 0 {
		t.Fatal("no counters stored")
	}
	for _, k := range keys {
		if ttl := client.PTTL(ctx, k).Val(); ttl <= 0 {
			t.Errorf("key %s has no expiry", k)
		}
	}
}
