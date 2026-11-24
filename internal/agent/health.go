package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/platform/httpserver"
	"github.com/the-asmit/nook/internal/platform/metrics"
	"github.com/the-asmit/nook/internal/version"
)

// agentMetrics are the agent's Prometheus metrics.
type agentMetrics struct {
	registry   *prometheus.Registry
	heartbeats prometheus.Counter
	reconnects prometheus.Counter
	commands   *prometheus.CounterVec
	certExpiry prometheus.Gauge
}

func newAgentMetrics() (*agentMetrics, error) {
	reg, err := metrics.NewRegistry("nook-agent", version.Get())
	if err != nil {
		return nil, err
	}
	m := &agentMetrics{
		registry: reg,
		heartbeats: prometheus.NewCounter(prometheus.CounterOpts{Namespace: metrics.Namespace, Subsystem: "agent",
			Name: "heartbeats_sent_total", Help: "Heartbeats sent to the control plane."}),
		reconnects: prometheus.NewCounter(prometheus.CounterOpts{Namespace: metrics.Namespace, Subsystem: "agent",
			Name: "reconnects_total", Help: "Times the session with the control plane was re-established."}),
		commands: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: metrics.Namespace, Subsystem: "agent",
			Name: "commands_total", Help: "Commands executed, by kind and result."}, []string{"kind", "result"}),
		certExpiry: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: metrics.Namespace, Subsystem: "agent",
			Name: "certificate_expiry_timestamp_seconds", Help: "When the node's client certificate expires (Unix time)."}),
	}
	for _, c := range []prometheus.Collector{m.heartbeats, m.reconnects, m.commands, m.certExpiry} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register agent metrics: %w", err)
		}
	}
	return m, nil
}

// healthStatus is the /readyz body.
type healthStatus struct {
	Status    string `json:"status"`
	Connected bool   `json:"connected"`
	NodeID    string `json:"node_id"`
}

// ServeHealth serves /healthz, /readyz and /metrics on the configured
// address (loopback by default) until ctx is done.
func (a *Agent) ServeHealth(ctx context.Context, logger *slog.Logger) error {
	connected := prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: metrics.Namespace, Subsystem: "agent",
		Name: "connected", Help: "1 while a session with the control plane is established."},
		func() float64 {
			if a.Connected() {
				return 1
			}
			return 0
		})
	if err := a.metrics.registry.Register(connected); err != nil {
		return fmt.Errorf("register agent metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		st := healthStatus{Status: "ready", Connected: a.Connected(), NodeID: a.NodeID()}
		code := http.StatusOK
		if !st.Connected {
			st.Status, code = "not_connected", http.StatusServiceUnavailable
		}
		writeJSON(w, code, st)
	})
	mux.Handle("GET /metrics", metrics.Handler(a.metrics.registry))

	srv, err := httpserver.Listen(ctx, &httpserver.Config{
		Addr: a.cfg.HealthAddr, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute, ShutdownTimeout: 5 * time.Second,
	}, mux, logger)
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "agent health endpoint listening", "addr", srv.Addr().String())
	return srv.Serve(ctx)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
