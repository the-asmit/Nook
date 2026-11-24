// Package ratelimit implements fixed-window rate limits shared by every
// server instance through Redis.
package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Rule is a limit: at most Limit events per Window for one key.
type Rule struct {
	// Name namespaces the counters, e.g. "device_create".
	Name   string
	Limit  int
	Window time.Duration
}

// Result is the outcome of one Allow call.
type Result struct {
	Allowed bool
	// RetryAfter is how long until the current window ends.
	RetryAfter time.Duration
}

// Limiter counts events in Redis.
type Limiter struct {
	client *goredis.Client
}

// New returns a limiter backed by client.
func New(client *goredis.Client) *Limiter {
	return &Limiter{client: client}
}

// incrScript increments the window's counter and sets its expiry in one
// atomic step, so a crash between the two can never leave an immortal key.
// It returns the new count and the remaining time to live in milliseconds.
var incrScript = goredis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return {count, redis.call("PTTL", KEYS[1])}
`)

// keyPrefix keeps rate-limit counters apart from other Redis data.
const keyPrefix = "nook:ratelimit:"

// Allow records one event for key under rule and reports whether it is
// within the limit. Fixed windows allow short bursts of up to 2*Limit
// across a window boundary, which is acceptable for abuse protection.
func (l *Limiter) Allow(ctx context.Context, rule Rule, key string) (Result, error) {
	window := rule.Window.Milliseconds()
	slot := time.Now().UnixMilli() / window
	redisKey := keyPrefix + rule.Name + ":" + key + ":" + strconv.FormatInt(slot, 10)

	vals, err := incrScript.Run(ctx, l.client, []string{redisKey}, window).Int64Slice()
	if err != nil {
		return Result{}, fmt.Errorf("rate limit %s: %w", rule.Name, err)
	}
	count, ttl := vals[0], vals[1]
	return Result{
		Allowed:    count <= int64(rule.Limit),
		RetryAfter: time.Duration(max(ttl, 0)) * time.Millisecond,
	}, nil
}
