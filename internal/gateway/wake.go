package gateway

import (
	"context"
	"errors"
	"sync"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/routes"
)

// Waking holds requests for a sleeping app until it serves again.
//
// The first request for a sleeping app on this gateway starts one wake
// episode (singleflight): one call to the control plane, whose
// compare-and-set makes one wake across every gateway, then a wait for
// the app's route to be served, woken by route changes and polled as a
// fallback. Every other request for the app joins the episode instead of
// calling again. At most WakeMaxHeld requests per app wait on a gateway
// (backpressure: a burst cannot pile up connections without bound); the
// rest, and all of them after WakeTimeout, get 503 with Retry-After.

// wakePoll is how often a waiting episode re-reads the app's route from
// the control plane, in case a route event was lost.
const wakePoll = time.Second

// wakeRetryAfter is the Retry-After for requests refused while waking.
const wakeRetryAfter = "5"

// waker coalesces the wake-ups of this gateway.
type waker struct {
	wake    func(ctx context.Context, app uuid.UUID) error
	table   *table
	timeout time.Duration
	maxHeld int
	m       *metrics
	now     func() time.Time

	mu       sync.Mutex
	episodes map[uuid.UUID]*episode
}

// episode is one app's wake on this gateway.
type episode struct {
	held int
	done chan struct{}
	// Set before done is closed.
	route routes.Route
	err   error
}

// Errors of a held request.
var (
	errWakeBusy    = errors.New("too many requests are waiting for this app to wake")
	errWakeTimeout = errors.New("the app did not wake in time")
)

func newWaker(wake func(context.Context, uuid.UUID) error, tbl *table, timeout time.Duration, maxHeld int, m *metrics) *waker {
	return &waker{wake: wake, table: tbl, timeout: timeout, maxHeld: maxHeld, m: m, now: time.Now, episodes: map[uuid.UUID]*episode{}}
}

// hold waits until the app of route is served (returning its route), the
// wake fails or times out, too many requests already wait, or ctx ends.
func (w *waker) hold(ctx context.Context, route *routes.Route) (routes.Route, error) {
	w.mu.Lock()
	ep, ok := w.episodes[route.AppID]
	if !ok {
		ep = &episode{done: make(chan struct{})}
		w.episodes[route.AppID] = ep
		wanted := *route
		go w.run(ep, &wanted) //nolint:contextcheck,gosec // G118: the wake outlives the request that started it (its own timeout).
	}
	if ep.held >= w.maxHeld {
		w.mu.Unlock()
		w.m.wakeRefused.WithLabelValues("limit").Inc()
		return routes.Route{}, errWakeBusy
	}
	ep.held++
	w.m.wakeHeld.Inc()
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		ep.held--
		w.mu.Unlock()
		w.m.wakeHeld.Dec()
	}()
	select {
	case <-ep.done:
		if ep.err != nil {
			w.m.wakeRefused.WithLabelValues("timeout").Inc()
		}
		return ep.route, ep.err
	case <-ctx.Done():
		return routes.Route{}, ctx.Err()
	}
}

// run wakes the app and waits until its route is served or the timeout,
// then releases every held request.
func (w *waker) run(ep *episode, route *routes.Route) {
	start := w.now()
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()
	ep.route, ep.err = w.await(ctx, route)
	if ep.err == nil {
		w.m.wake.Observe(w.now().Sub(start).Seconds())
	}
	w.mu.Lock()
	delete(w.episodes, route.AppID)
	w.mu.Unlock()
	close(ep.done)
}

func (w *waker) await(ctx context.Context, route *routes.Route) (routes.Route, error) {
	called := false
	poll := time.NewTicker(wakePoll)
	defer poll.Stop()
	for {
		changed := w.table.Changed()
		r, ok := w.table.lookup(route.Host)
		if !ok {
			return routes.Route{}, routes.ErrNotFound // deleted meanwhile
		}
		if r.Serving() {
			return r, nil
		}
		if !called {
			// Retried at the next poll if the control plane was unreachable.
			called = w.wake(ctx, route.AppID) == nil
		}
		select {
		case <-ctx.Done():
			return routes.Route{}, errWakeTimeout
		case <-changed:
		case <-poll.C:
			_ = w.table.refresh(ctx, route.AppID)
		}
	}
}
