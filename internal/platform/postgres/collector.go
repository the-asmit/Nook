package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/platform/metrics"
)

// PoolCollector exports connection pool statistics. Pool saturation
// (acquired == max, rising empty acquires) is usually the first sign of a
// database bottleneck, long before queries themselves slow down.
type PoolCollector struct {
	pool *pgxpool.Pool

	acquired, idle, constructing, total, max *prometheus.Desc
	acquires, emptyAcquires, canceled        *prometheus.Desc
	acquireSeconds                           *prometheus.Desc
}

// NewPoolCollector returns a collector reading stats from pool on every scrape.
func NewPoolCollector(pool *pgxpool.Pool) *PoolCollector {
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(metrics.Namespace, "postgres_pool", name), help, nil, nil)
	}
	return &PoolCollector{
		pool:           pool,
		acquired:       desc("acquired_conns", "Connections currently checked out of the pool."),
		idle:           desc("idle_conns", "Idle connections in the pool."),
		constructing:   desc("constructing_conns", "Connections currently being established."),
		total:          desc("total_conns", "Total connections in the pool."),
		max:            desc("max_conns", "Configured maximum pool size."),
		acquires:       desc("acquires_total", "Successful connection acquisitions."),
		emptyAcquires:  desc("empty_acquires_total", "Acquisitions that had to wait because the pool was empty."),
		canceled:       desc("canceled_acquires_total", "Acquisitions canceled by their context while waiting."),
		acquireSeconds: desc("acquire_duration_seconds_total", "Total time spent waiting to acquire connections."),
	}
}

// Describe implements prometheus.Collector.
func (c *PoolCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.acquired, c.idle, c.constructing, c.total, c.max,
		c.acquires, c.emptyAcquires, c.canceled, c.acquireSeconds,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *PoolCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.pool.Stat()
	emit := func(d *prometheus.Desc, t prometheus.ValueType, v float64) {
		m, err := prometheus.NewConstMetric(d, t, v)
		if err != nil {
			// Surfaces in the scrape as an error instead of crashing the process.
			m = prometheus.NewInvalidMetric(d, err)
		}
		ch <- m
	}
	gauge := func(d *prometheus.Desc, v float64) { emit(d, prometheus.GaugeValue, v) }
	counter := func(d *prometheus.Desc, v float64) { emit(d, prometheus.CounterValue, v) }
	gauge(c.acquired, float64(s.AcquiredConns()))
	gauge(c.idle, float64(s.IdleConns()))
	gauge(c.constructing, float64(s.ConstructingConns()))
	gauge(c.total, float64(s.TotalConns()))
	gauge(c.max, float64(s.MaxConns()))
	counter(c.acquires, float64(s.AcquireCount()))
	counter(c.emptyAcquires, float64(s.EmptyAcquireCount()))
	counter(c.canceled, float64(s.CanceledAcquireCount()))
	counter(c.acquireSeconds, s.AcquireDuration().Seconds())
}
