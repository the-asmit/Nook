package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/health"
	"github.com/the-asmit/nook/internal/platform/httpserver"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func httpConfig() httpserver.Config {
	return httpserver.Config{MaxBodyBytes: 1 << 20, RequestTimeout: 5 * time.Second}
}

func newTestRouter(t *testing.T, logs io.Writer, checks ...health.Check) *gin.Engine {
	t.Helper()
	r, err := NewRouter(&Deps{
		Logger:           slog.New(slog.NewJSONHandler(logs, nil)),
		Registry:         prometheus.NewRegistry(),
		HTTP:             httpConfig(),
		ReadinessChecks:  checks,
		ReadinessTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func do(r http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, http.NoBody))
	return rec
}

func passing(name string) health.Check {
	return health.Check{Name: name, Probe: func(context.Context) error { return nil }}
}

func failing(name string) health.Check {
	return health.Check{Name: name, Probe: func(context.Context) error { return errors.New("connection refused to db.internal:5432") }}
}

func TestHealthz(t *testing.T) {
	rec := do(newTestRouter(t, io.Discard, failing("postgres")), http.MethodGet, RouteHealthz)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("liveness must not depend on dependencies: %d %s", rec.Code, rec.Body.String())
	}
}

func TestReadyzAllHealthy(t *testing.T) {
	rec := do(newTestRouter(t, io.Discard, passing("postgres"), passing("redis")), http.MethodGet, RouteReadyz)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body ReadinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ready" || body.Checks["postgres"] != checkOK || body.Checks["redis"] != checkOK || body.Failing != nil {
		t.Fatalf("body = %+v", body)
	}
}

func TestReadyzNamesFailingDependency(t *testing.T) {
	var logs bytes.Buffer
	rec := do(newTestRouter(t, &logs, failing("postgres"), passing("redis")), http.MethodGet, RouteReadyz)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body ReadinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "not_ready" || !slices.Equal(body.Failing, []string{"postgres"}) ||
		body.Checks["postgres"] != checkUnavailable || body.Checks["redis"] != checkOK {
		t.Fatalf("body = %+v", body)
	}
	if strings.Contains(rec.Body.String(), "db.internal") {
		t.Error("internal error details must not appear in the response")
	}
	if !strings.Contains(logs.String(), "db.internal") {
		t.Error("error details should be logged")
	}
}

func TestMetricsEndpointExposesHTTPMetrics(t *testing.T) {
	r := newTestRouter(t, io.Discard)
	do(r, http.MethodGet, RouteHealthz)
	rec := do(r, http.MethodGet, RouteMetrics)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	want := `nook_http_requests_total{method="GET",route="/healthz",status="200"} 1`
	if !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("metrics missing %q:\n%s", want, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "nook_http_request_duration_seconds_bucket") {
		t.Fatal("latency histogram missing")
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	r := newTestRouter(t, io.Discard)

	rec := do(r, http.MethodGet, "/nope")
	var body httpserver.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusNotFound || body.Error.Code != "not_found" {
		t.Fatalf("404: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(r, http.MethodPost, RouteHealthz)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusMethodNotAllowed || body.Error.Code != "method_not_allowed" {
		t.Fatalf("405: %d %s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareChainIsApplied(t *testing.T) {
	rec := do(newTestRouter(t, io.Discard), http.MethodGet, RouteHealthz)
	if rec.Header().Get(httpserver.HeaderRequestID) == "" {
		t.Error("request ID header missing")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers missing")
	}
}

func TestClientIPIgnoresForwardedForWithoutTrustedProxies(t *testing.T) {
	var logs bytes.Buffer
	r := newTestRouter(t, &logs)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/nope", http.NoBody)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	r.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(logs.String(), `"client_ip":"192.0.2.10"`) {
		t.Fatalf("spoofed X-Forwarded-For was trusted: %s", logs.String())
	}
}

func TestNewRouterValidatesDeps(t *testing.T) {
	if _, err := NewRouter(nil); err == nil {
		t.Error("nil deps should fail")
	}
	if _, err := NewRouter(&Deps{}); err == nil {
		t.Error("missing logger/registry should fail")
	}
	_, err := NewRouter(&Deps{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Registry: prometheus.NewRegistry(),
		HTTP:     httpserver.Config{TrustedProxies: []string{"bogus"}, MaxBodyBytes: 1, RequestTimeout: time.Second},
	})
	if err == nil {
		t.Error("invalid trusted proxy should fail")
	}
}

func TestConfigureGin(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { gin.SetMode(gin.TestMode) })

	ConfigureGin(config.Production, logger)
	if gin.Mode() != gin.ReleaseMode {
		t.Errorf("production mode = %s", gin.Mode())
	}
	ConfigureGin(config.Development, logger)
	if gin.Mode() != gin.DebugMode {
		t.Errorf("development mode = %s", gin.Mode())
	}
}
