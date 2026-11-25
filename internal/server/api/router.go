// Package api assembles the control plane's HTTP API: the Gin router, the
// middleware chain and the handlers.
package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/health"
	"github.com/the-asmit/nook/internal/platform/httpserver"
	"github.com/the-asmit/nook/internal/platform/metrics"
)

// Routes served by the operational endpoints.
const (
	RouteHealthz = "/healthz"
	RouteReadyz  = "/readyz"
	RouteMetrics = "/metrics"
)

// Deps are the collaborators the router needs.
type Deps struct {
	Logger   *slog.Logger
	Registry *prometheus.Registry
	HTTP     httpserver.Config
	// ReadinessChecks are the dependencies /readyz probes.
	ReadinessChecks []health.Check
	// ReadinessTimeout bounds each readiness probe.
	ReadinessTimeout time.Duration
	// StreamingRoutes are exempt from the request timeout.
	StreamingRoutes []string
}

// ConfigureGin sets Gin's process-wide mode. Debug mode (route dumps,
// warnings) is only useful during development; elsewhere it is noise and
// slightly slower. Gin's debug output is routed through the JSON logger.
// It mutates package-level state in Gin, so call it once from main.
func ConfigureGin(env config.Environment, logger *slog.Logger) {
	if !env.IsDevelopment() {
		gin.SetMode(gin.ReleaseMode)
		return
	}
	gin.SetMode(gin.DebugMode)
	gin.DebugPrintFunc = func(format string, values ...any) {
		logger.Debug("gin", "detail", strings.TrimSpace(fmt.Sprintf(format, values...)))
	}
	gin.DebugPrintRouteFunc = func(method, path, handler string, _ int) {
		logger.Debug("route registered", "method", method, "path", path, "handler", handler)
	}
}

// NewRouter builds the HTTP handler for the control plane.
func NewRouter(d *Deps) (*gin.Engine, error) {
	if d == nil || d.Logger == nil || d.Registry == nil {
		return nil, errors.New("api: logger and registry are required")
	}
	httpMetrics, err := httpserver.NewHTTPMetrics(d.Registry)
	if err != nil {
		return nil, err
	}

	r := gin.New()
	// Trust X-Forwarded-For only from configured proxies; otherwise any
	// client could choose the IP that appears in our logs.
	if err := r.SetTrustedProxies(d.HTTP.TrustedProxies); err != nil {
		return nil, fmt.Errorf("set trusted proxies: %w", err)
	}
	r.HandleMethodNotAllowed = true

	// Order matters. The request ID comes first so every later log line
	// carries it. Access logging and metrics wrap Recovery so a panicking
	// request is still logged and counted, as the 500 Recovery produces.
	r.Use(
		httpserver.RequestID(),
		httpserver.AccessLog(d.Logger, RouteHealthz, RouteReadyz, RouteMetrics),
		httpMetrics.Middleware(),
		httpserver.Recovery(d.Logger),
		httpserver.SecurityHeaders(),
		httpserver.BodyLimit(d.HTTP.MaxBodyBytes),
		httpserver.RequestTimeout(d.HTTP.RequestTimeout, d.StreamingRoutes...),
	)

	r.NoRoute(func(c *gin.Context) {
		httpserver.AbortWithError(c, http.StatusNotFound, "not_found", "no such endpoint")
	})
	r.NoMethod(func(c *gin.Context) {
		httpserver.AbortWithError(c, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed for this endpoint")
	})

	h := &healthHandlers{logger: d.Logger, checks: d.ReadinessChecks, timeout: d.ReadinessTimeout}
	r.GET(RouteHealthz, h.liveness)
	r.GET(RouteReadyz, h.readiness)
	r.GET(RouteMetrics, gin.WrapH(metrics.Handler(d.Registry)))
	return r, nil
}
