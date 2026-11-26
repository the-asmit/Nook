package gateway

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/routes"
)

// source is where the table reads routes (the control plane).
type source interface {
	routes(ctx context.Context) ([]routes.Route, error)
	route(ctx context.Context, appID uuid.UUID) (routes.Route, error)
}

// table is the in-memory route table: host → route. It is loaded in full
// at start, updated per app from Pub/Sub events and fully resynced on a
// timer, so a missed event (a Redis hiccup, a gateway that was
// reconnecting) heals at the next resync: eventual consistency with a
// bounded delay.
type table struct {
	src    source
	logger *slog.Logger
	m      *metrics

	mu     sync.RWMutex
	byHost map[string]routes.Route
	byApp  map[uuid.UUID]string
	// changed is closed (and replaced) whenever routes change, so requests
	// waiting for an app to wake see its route at once.
	changed chan struct{}
	loaded  atomic.Bool
}

func newTable(src source, logger *slog.Logger, m *metrics) *table {
	return &table{src: src, logger: logger, m: m, byHost: map[string]routes.Route{}, byApp: map[uuid.UUID]string{}, changed: make(chan struct{})}
}

// Changed returns a channel closed at the next change of the table.
func (t *table) Changed() <-chan struct{} {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.changed
}

// notify wakes the waiters; t.mu must be held for writing.
func (t *table) notify() {
	close(t.changed)
	t.changed = make(chan struct{})
}

// lookup returns the route for a host.
func (t *table) lookup(host string) (routes.Route, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	r, ok := t.byHost[host]
	return r, ok
}

// size returns the number of routes.
func (t *table) size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byHost)
}

// resync replaces the table with the control plane's full list.
func (t *table) resync(ctx context.Context) error {
	list, err := t.src.routes(ctx)
	if err != nil {
		return err
	}
	byHost := make(map[string]routes.Route, len(list))
	byApp := make(map[uuid.UUID]string, len(list))
	for _, r := range list {
		byHost[r.Host] = r
		byApp[r.AppID] = r.Host
	}
	t.mu.Lock()
	t.byHost, t.byApp = byHost, byApp
	t.notify()
	t.mu.Unlock()
	t.loaded.Store(true)
	t.m.routes.Set(float64(len(byHost)))
	t.m.resyncs.Inc()
	return nil
}

// refresh reloads one app's route after an event. A failed fetch keeps
// the route as it was (the next resync catches up); only a confirmed
// deletion removes it.
func (t *table) refresh(ctx context.Context, appID uuid.UUID) error {
	r, err := t.src.route(ctx, appID)
	if err != nil && !errors.Is(err, routes.ErrNotFound) {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	defer t.notify()
	if old, ok := t.byApp[appID]; ok {
		delete(t.byHost, old)
		delete(t.byApp, appID)
	}
	if err == nil {
		t.byHost[r.Host] = r
		t.byApp[r.AppID] = r.Host
	}
	t.m.routes.Set(float64(len(t.byHost)))
	return nil
}

// run keeps the table current until ctx ends: events from Pub/Sub, a full
// resync every interval and after every (re)subscription.
func (t *table) run(ctx context.Context, rdb *goredis.Client, interval time.Duration) {
	events := make(chan uuid.UUID, 256)
	go t.subscribe(ctx, rdb, events)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-events:
			if id == uuid.Nil() {
				// Resubscribed: events may have been missed meanwhile.
				t.resyncLogged(ctx)
				continue
			}
			if err := t.refresh(ctx, id); err != nil && ctx.Err() == nil {
				t.logger.WarnContext(ctx, "could not refresh a route; the next resync catches up", "app", id.String(), "error", err.Error())
			}
		case <-ticker.C:
			t.resyncLogged(ctx)
		}
	}
}

func (t *table) resyncLogged(ctx context.Context) {
	if err := t.resync(ctx); err != nil && ctx.Err() == nil {
		t.logger.WarnContext(ctx, "route resync failed; serving the last known routes", "error", err.Error())
	}
}

// subscribe forwards route events, re-subscribing after errors; uuid.Nil()
// signals a (re)subscription.
func (t *table) subscribe(ctx context.Context, rdb *goredis.Client, events chan<- uuid.UUID) {
	for ctx.Err() == nil {
		sub := rdb.Subscribe(ctx, routes.Channel)
		if _, err := sub.Receive(ctx); err != nil {
			_ = sub.Close()
			if ctx.Err() == nil {
				t.logger.WarnContext(ctx, "route events unavailable; retrying", "error", err.Error())
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		select {
		case events <- uuid.Nil():
		case <-ctx.Done():
		}
		ch := sub.Channel()
		for open := true; open; {
			select {
			case <-ctx.Done():
				_ = sub.Close()
				return
			case msg, ok := <-ch:
				if !ok {
					open = false
					break
				}
				if id, err := uuid.Parse(msg.Payload); err == nil {
					select {
					case events <- id:
					default:
						// Full: the resync below covers what is dropped.
						select {
						case events <- uuid.Nil():
						default:
						}
					}
				}
			}
		}
		_ = sub.Close()
	}
}
