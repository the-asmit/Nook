package rollout

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/store"
)

// metrics are the controller's Prometheus metrics: wake and failover
// times (what a visitor of a sleeping app and the users of a failed node
// wait), sleeps and wakes, and on every scrape the apps asleep and
// running and the memory sleeping apps released.
type metrics struct {
	wake     prometheus.Histogram
	failover prometheus.Histogram
	moved    prometheus.Histogram
	sleeps   *prometheus.CounterVec
	wakes    prometheus.Counter
}

func newMetrics(reg prometheus.Registerer, st *store.Store) (*metrics, error) {
	m := &metrics{
		wake: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "nook_app_wake_seconds", Help: "Time from a wake request to the woken instance being healthy (control plane's view).",
			Buckets: []float64{0.25, 0.5, 1, 2, 3, 5, 8, 13, 21, 30, 60},
		}),
		failover: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "nook_app_failover_seconds", Help: "Time from a node being declared dead to its app being healthy on another node.",
			Buckets: []float64{1, 2, 5, 10, 15, 20, 30, 45, 60, 90, 120, 300},
		}),
		moved: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "nook_app_drain_move_seconds", Help: "Time to start an app's replacement when its node is drained (until healthy).",
			Buckets: []float64{1, 2, 5, 10, 20, 30, 60, 120},
		}),
		sleeps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nook_app_sleeps_total", Help: "Apps put to sleep, by reason (idle, or evicted to make room).",
		}, []string{"reason"}),
		wakes: prometheus.NewCounter(prometheus.CounterOpts{Name: "nook_app_wakes_total", Help: "Sleeping apps woken."}),
	}
	for _, c := range []prometheus.Collector{m.wake, m.failover, m.moved, m.sleeps, m.wakes, &appStates{store: st}} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register rollout metrics: %w", err)
		}
	}
	return m, nil
}

// appStates reports, at scrape time, how many apps sleep and run and the
// memory reservations sleeping apps released (from the database, so every
// control-plane instance reports the same numbers).
type appStates struct {
	store *store.Store
}

var (
	sleepingDesc = prometheus.NewDesc("nook_apps_sleeping", "Apps asleep.", nil, nil)
	runningDesc  = prometheus.NewDesc("nook_apps_running", "Apps with a running instance.", nil, nil)
	releasedDesc = prometheus.NewDesc("nook_apps_sleeping_released_memory_bytes", "Memory reservations released by sleeping apps.", nil, nil)
)

// Describe implements prometheus.Collector.
func (a *appStates) Describe(ch chan<- *prometheus.Desc) {
	ch <- sleepingDesc
	ch <- runningDesc
	ch <- releasedDesc
}

// Collect implements prometheus.Collector.
func (a *appStates) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if sleeping, err := a.store.CountSleepingApps(ctx); err == nil {
		ch <- prometheus.MustNewConstMetric(sleepingDesc, prometheus.GaugeValue, float64(sleeping.Apps))
		ch <- prometheus.MustNewConstMetric(releasedDesc, prometheus.GaugeValue, float64(sleeping.MemoryMb<<20))
	}
	if running, err := a.store.CountRunningApps(ctx); err == nil {
		ch <- prometheus.MustNewConstMetric(runningDesc, prometheus.GaugeValue, float64(running))
	}
}
