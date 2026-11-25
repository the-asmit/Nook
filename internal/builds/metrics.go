package builds

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	dispatched prometheus.Counter
	finished   *prometheus.CounterVec
	queueWait  prometheus.Histogram
	duration   prometheus.Histogram
}

func newMetrics(reg prometheus.Registerer) (*metrics, error) {
	m := &metrics{
		dispatched: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nook_builds_dispatched_total", Help: "Build attempts handed to a node.",
		}),
		finished: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nook_builds_finished_total", Help: "Build attempts by outcome.",
		}, []string{"result"}),
		queueWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "nook_build_queue_wait_seconds", Help: "Time from queueing to dispatch.",
			Buckets: prometheus.ExponentialBuckets(0.1, 3, 10),
		}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "nook_build_duration_seconds", Help: "Duration of finished build attempts.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
		}),
	}
	for _, c := range []prometheus.Collector{m.dispatched, m.finished, m.queueWait, m.duration} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register build metrics: %w", err)
		}
	}
	return m, nil
}
