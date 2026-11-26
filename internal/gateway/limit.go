package gateway

import (
	"sync"
	"time"
)

// limiter is a token bucket per key (client IP, app), in memory. Limits
// are per gateway instance: with N instances behind a load balancer a
// client may get up to N times the rate.
type limiter struct {
	rate  float64
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
	swept   time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate float64, burst int) *limiter {
	return &limiter{rate: rate, burst: float64(burst), now: time.Now, buckets: map[string]*bucket{}}
}

// idleAfter: a bucket unused this long is full again and can be dropped.
func (l *limiter) idleAfter() time.Duration {
	return time.Duration(l.burst/l.rate*float64(time.Second)) + time.Minute
}

// allow takes a token for key.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.swept) > time.Minute {
		l.sweep(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) sweep(now time.Time) {
	l.swept = now
	idle := l.idleAfter()
	for k, b := range l.buckets {
		if now.Sub(b.last) > idle {
			delete(l.buckets, k)
		}
	}
}
