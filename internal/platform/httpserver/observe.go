package httpserver

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/platform/metrics"
)

// unmatchedRoute labels requests that matched no route. Using the raw path
// instead would let any client create unbounded metric series.
const unmatchedRoute = "unmatched"

// Bounds for client-controlled strings written to access logs.
const (
	maxLoggedPathLength      = 512
	maxLoggedUserAgentLength = 256
)

// Recovery turns a panicking handler into a logged 500 response instead of
// a dropped connection. It must run inside AccessLog and Metrics so those
// still record the request.
func Recovery(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			logger.ErrorContext(c.Request.Context(), "panic while handling request",
				"panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
			if c.Writer.Written() {
				// Headers are gone; the best we can do is stop the chain.
				c.Abort()
				return
			}
			AbortWithError(c, http.StatusInternalServerError, "internal", "internal server error")
		}()
		c.Next()
	}
}

// AccessLog writes one structured log line per request. Requests to
// quietRoutes (health probes, metrics scrapes) are logged at debug level
// when they succeed, so probes every few seconds do not drown real traffic.
func AccessLog(logger *slog.Logger, quietRoutes ...string) gin.HandlerFunc {
	quiet := make(map[string]bool, len(quietRoutes))
	for _, r := range quietRoutes {
		quiet[r] = true
	}
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		status := c.Writer.Status()
		route := routeOf(c)
		level := slog.LevelInfo
		switch {
		case status >= http.StatusInternalServerError:
			level = slog.LevelError
		case quiet[route] && status < http.StatusBadRequest:
			level = slog.LevelDebug
		}
		logger.LogAttrs(c.Request.Context(), level, "http request",
			slog.String("method", c.Request.Method),
			slog.String("route", route),
			// Path only: query strings may carry tokens.
			slog.String("path", truncate(c.Request.URL.Path, maxLoggedPathLength)),
			slog.Int("status", status),
			slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
			slog.Int("bytes", max(c.Writer.Size(), 0)),
			slog.String("client_ip", c.ClientIP()),
			slog.String("user_agent", truncate(c.Request.UserAgent(), maxLoggedUserAgentLength)),
		)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func routeOf(c *gin.Context) string {
	if r := c.FullPath(); r != "" {
		return r
	}
	return unmatchedRoute
}

// HTTPMetrics records request counts, latencies and concurrency.
type HTTPMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight prometheus.Gauge
}

// NewHTTPMetrics creates the HTTP metrics and registers them with reg.
func NewHTTPMetrics(reg prometheus.Registerer) (*HTTPMetrics, error) {
	labels := []string{"method", "route", "status"}
	m := &HTTPMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace, Subsystem: "http", Name: "requests_total",
			Help: "HTTP requests handled, by method, route template and status code.",
		}, labels),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.Namespace, Subsystem: "http", Name: "request_duration_seconds",
			Help:    "HTTP request latency, by method, route template and status code.",
			Buckets: prometheus.DefBuckets,
		}, labels),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace, Subsystem: "http", Name: "requests_in_flight",
			Help: "HTTP requests currently being handled.",
		}),
	}
	for _, c := range []prometheus.Collector{m.requests, m.duration, m.inFlight} {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register http metrics: %w", err)
		}
	}
	return m, nil
}

// Middleware returns the Gin middleware that feeds these metrics.
func (m *HTTPMetrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		m.inFlight.Inc()
		defer m.inFlight.Dec()
		start := time.Now()
		c.Next()

		method := normalizeMethod(c.Request.Method)
		route := routeOf(c)
		status := strconv.Itoa(c.Writer.Status())
		m.requests.WithLabelValues(method, route, status).Inc()
		m.duration.WithLabelValues(method, route, status).Observe(time.Since(start).Seconds())
	}
}

// normalizeMethod maps non-standard methods to "OTHER": the method is
// client-controlled and must not create unbounded label values.
func normalizeMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	default:
		return "OTHER"
	}
}
