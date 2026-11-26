package gateway

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics are the gateway's Prometheus metrics. The app label is
// "<workspace>/<app>" (bounded by the number of apps), "-" for requests
// without a known app and "auth" for the auth host.
type metrics struct {
	requests  *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	upgraded  prometheus.Gauge
	routes    prometheus.Gauge
	resyncs   prometheus.Counter
	limited   *prometheus.CounterVec
	authCheck *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) (*metrics, error) {
	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nook_gateway_requests_total", Help: "Requests by app and status code.",
		}, []string{"app", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "nook_gateway_request_duration_seconds", Help: "Request duration until the response ended (upgraded connections: until closed), by app.",
			Buckets: prometheus.DefBuckets,
		}, []string{"app"}),
		upgraded: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "nook_gateway_upgraded_connections", Help: "Open upgraded (WebSocket) connections.",
		}),
		routes: prometheus.NewGauge(prometheus.GaugeOpts{Name: "nook_gateway_routes", Help: "Routes in the table."}),
		resyncs: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "nook_gateway_route_resyncs_total", Help: "Full route table loads.",
		}),
		limited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nook_gateway_rate_limited_total", Help: "Requests refused by a rate limit, by limit.",
		}, []string{"limit"}),
		authCheck: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nook_gateway_session_checks_total", Help: "Visitor session checks by result and whether the cache answered.",
		}, []string{"result", "cached"}),
	}
	for _, c := range []prometheus.Collector{m.requests, m.duration, m.upgraded, m.routes, m.resyncs, m.limited, m.authCheck} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register gateway metrics: %w", err)
		}
	}
	return m, nil
}
