package gateway

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/the-asmit/nook/internal/routes"
)

// TestConcurrentRequestsShareOneWake: 100 requests for a sleeping app at
// once make one wake call; every one of them is answered by the app once
// it serves, and the wake latency is recorded.
func TestConcurrentRequestsShareOneWake(t *testing.T) {
	f := newFixture(t, nil)
	up := newEchoUpstream(t)
	r := f.addApp("sleepy", routes.AccessPublic, routes.StateSleeping, "")

	const n = 100
	statuses := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { statuses[i] = f.do(http.MethodGet, r.Host, "/", nil, nil).status })
	}
	// Every request is held before the app comes up (it is "starting").
	waitFor(t, 10*time.Second, "100 held requests", func() bool { return testutil.ToFloat64(f.h.m.wakeHeld) == n })
	awake := r
	awake.State, awake.Upstream = routes.StateRunning, hostOf(up)
	f.cp.set(&awake)
	wg.Wait()
	for i, s := range statuses {
		if s != http.StatusOK {
			t.Fatalf("request %d: status %d", i, s)
		}
	}
	if w := f.cp.wakeCount(); w != 1 {
		t.Fatalf("%d wake calls for %d concurrent requests, want 1", w, n)
	}
	if c := f.metric("nook_gateway_wake_seconds_count"); c != 1 {
		t.Fatalf("wake latency recorded %v times, want once", c)
	}
	// Awake now: the next request goes straight through, no new wake.
	if s := f.do(http.MethodGet, r.Host, "/", nil, nil).status; s != http.StatusOK || f.cp.wakeCount() != 1 {
		t.Fatalf("after waking: %d, %d wakes", s, f.cp.wakeCount())
	}
}

// TestWakeBackpressureAndTimeout: at most WakeMaxHeld requests wait for
// an app to wake; the rest get 503 with Retry-After at once, and the ones
// waiting get the same after the wake timeout.
func TestWakeBackpressureAndTimeout(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.WakeMaxHeld, c.WakeTimeout = 3, time.Second })
	r := f.addApp("stuck", routes.AccessPublic, routes.StateSleeping, "") // never wakes

	const n = 10
	results := make([]result, n)
	var wg sync.WaitGroup
	start := time.Now()
	for i := range n {
		wg.Go(func() { results[i] = f.do(http.MethodGet, r.Host, "/", nil, nil) })
	}
	wg.Wait()
	for i, res := range results {
		if res.status != http.StatusServiceUnavailable || res.header.Get("Retry-After") != wakeRetryAfter {
			t.Fatalf("request %d: status %d, Retry-After %q", i, res.status, res.header.Get("Retry-After"))
		}
	}
	if d := time.Since(start); d < time.Second {
		t.Fatalf("the held requests were answered after %s, before the wake timeout", d)
	}
	limit := testutil.ToFloat64(f.h.m.wakeRefused.WithLabelValues("limit"))
	timeout := testutil.ToFloat64(f.h.m.wakeRefused.WithLabelValues("timeout"))
	if limit != n-3 || timeout != 3 {
		t.Fatalf("refused: %v over the limit, %v timed out; want %d and 3", limit, timeout, n-3)
	}
	if held := testutil.ToFloat64(f.h.m.wakeHeld); held != 0 {
		t.Fatalf("%v requests still counted as held", held)
	}
}
