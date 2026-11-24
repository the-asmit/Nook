//go:build integration

package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/testinfra"
)

func TestFlowsAreSingleUseAndStoredByDigest(t *testing.T) {
	_, url := testinfra.RedisT(t)
	opts, err := goredis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	client := goredis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	f := NewFlows(client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	id, flow, err := f.Begin(ctx, "//evil.example")
	if err != nil {
		t.Fatal(err)
	}
	if flow.ReturnTo != "/" || flow.State == "" || flow.Nonce == "" || len(flow.Verifier) < 43 {
		t.Fatalf("flow = %+v", flow)
	}
	keys := client.Keys(ctx, "nook:signin:*").Val()
	if len(keys) != 1 || strings.Contains(keys[0], id) {
		t.Fatalf("flow must be stored under a digest of its ID: %v", keys)
	}
	if ttl := client.TTL(ctx, keys[0]).Val(); ttl <= 0 || ttl > FlowTTL {
		t.Fatalf("ttl = %v", ttl)
	}

	got, err := f.Take(ctx, id)
	if err != nil || got != flow {
		t.Fatalf("Take = %+v, %v", got, err)
	}
	if _, err := f.Take(ctx, id); !errors.Is(err, ErrFlowNotFound) {
		t.Fatalf("second Take: %v", err)
	}
	if _, err := f.Take(ctx, "not-a-flow-id"); !errors.Is(err, ErrFlowNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
}
