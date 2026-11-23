package httpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/the-asmit/nook/internal/platform/logging"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

func newEngine(mw ...gin.HandlerFunc) *gin.Engine {
	e := gin.New()
	e.Use(mw...)
	return e
}

func serve(e http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) ErrorDetail {
	t.Helper()
	var body ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not the error envelope: %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

func TestRequestIDGeneratesAndPropagates(t *testing.T) {
	var seen string
	e := newEngine(RequestID())
	e.GET("/", func(c *gin.Context) { seen = logging.RequestIDFromContext(c.Request.Context()) })

	rec := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody))
	got := rec.Header().Get(HeaderRequestID)
	if got == "" || got != seen {
		t.Fatalf("header %q, context %q: want the same non-empty ID", got, seen)
	}
	if !validRequestID(got) {
		t.Fatalf("generated ID %q fails our own validation", got)
	}

	rec2 := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody))
	if rec2.Header().Get(HeaderRequestID) == got {
		t.Fatal("two requests got the same generated ID")
	}
}

func TestRequestIDAcceptsValidIncomingAndRejectsInvalid(t *testing.T) {
	e := newEngine(RequestID())
	e.GET("/", func(*gin.Context) {})

	tests := []struct {
		in   string
		keep bool
	}{
		{"abc-123_X.y", true},
		{"0e5a3a1e-2f7b-4c4e-9a43-1c1f9c0d5f11", true},
		{strings.Repeat("a", maxRequestIDLength), true},
		{strings.Repeat("a", maxRequestIDLength+1), false},
		{"has space", false},
		{"inject\nline", false},
		{"<script>", false},
	}
	for _, tt := range tests {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		req.Header.Set(HeaderRequestID, tt.in)
		got := serve(e, req).Header().Get(HeaderRequestID)
		if (got == tt.in) != tt.keep {
			t.Errorf("incoming %q -> %q, keep=%v", tt.in, got, tt.keep)
		}
		if got == "" {
			t.Errorf("incoming %q -> no ID at all", tt.in)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEngine(SecurityHeaders())
	e.GET("/", func(*gin.Context) {})

	rec := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody))
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Cache-Control":           "no-store",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be sent over plain HTTP")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.TLS = &tls.ConnectionState{}
	if serve(e, req).Header().Get("Strict-Transport-Security") == "" {
		t.Error("HSTS missing over HTTPS")
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEngine(RequestID(), BodyLimit(8))
	e.POST("/", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				AbortWithError(c, http.StatusRequestEntityTooLarge, "payload_too_large", "too large")
				return
			}
			c.Status(http.StatusBadRequest)
			return
		}
		c.Status(http.StatusNoContent)
	})

	if rec := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader("12345678"))); rec.Code != http.StatusNoContent {
		t.Fatalf("body at the limit: status %d", rec.Code)
	}

	rec := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader("123456789")))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared oversize body: status %d", rec.Code)
	}
	if d := decodeError(t, rec); d.Code != "payload_too_large" || d.RequestID == "" {
		t.Fatalf("error = %+v", d)
	}

	// Without a Content-Length the limit is enforced while reading.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", io.MultiReader(strings.NewReader("1234"), strings.NewReader("56789")))
	req.ContentLength = -1
	if rec := serve(e, req); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("streamed oversize body: status %d", rec.Code)
	}
}

func TestRequestTimeoutSetsDeadline(t *testing.T) {
	e := newEngine(RequestTimeout(time.Minute))
	e.GET("/", func(c *gin.Context) {
		deadline, ok := c.Request.Context().Deadline()
		if !ok || time.Until(deadline) > time.Minute {
			c.Status(http.StatusTeapot)
			return
		}
		c.Status(http.StatusOK)
	})
	if rec := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)); rec.Code != http.StatusOK {
		t.Fatalf("handler did not see the deadline: status %d", rec.Code)
	}
}

func TestRequestTimeoutAnswersForSilentHandler(t *testing.T) {
	e := newEngine(RequestTimeout(10 * time.Millisecond))
	e.GET("/", func(c *gin.Context) { <-c.Request.Context().Done() })

	rec := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if d := decodeError(t, rec); d.Code != "timeout" {
		t.Fatalf("code = %q", d.Code)
	}
}

func TestRecoveryReturns500AndLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	e := newEngine(RequestID(), Recovery(logger))
	e.GET("/boom", func(*gin.Context) { panic("kaboom") })
	e.GET("/late", func(c *gin.Context) {
		c.String(http.StatusOK, "partial")
		panic("after write")
	})

	rec := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/boom", http.NoBody))
	if rec.Code != http.StatusInternalServerError || decodeError(t, rec).Code != "internal" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(buf.String(), "kaboom") || !strings.Contains(buf.String(), "stack") {
		t.Fatalf("panic not logged: %s", buf.String())
	}

	rec = serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/late", http.NoBody))
	if rec.Code != http.StatusOK || rec.Body.String() != "partial" {
		t.Fatalf("already-written response was altered: %d %q", rec.Code, rec.Body.String())
	}
}

func TestAccessLog(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.New(&buf, logging.Config{Level: "info"})
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(RequestID(), AccessLog(logger, "/healthz"))
	e.GET("/items/:id", func(c *gin.Context) { c.String(http.StatusCreated, "hello") })
	e.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })
	e.GET("/fail", func(c *gin.Context) { c.Status(http.StatusInternalServerError) })

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/items/42?token=secret", http.NoBody)
	req.Header.Set("User-Agent", strings.Repeat("u", 1000))
	serve(e, req)
	serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody))
	serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fail", http.NoBody))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (healthz is debug-level): %s", len(lines), buf.String())
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatal(err)
	}
	checks := map[string]any{
		"msg": "http request", "method": "GET", "route": "/items/:id", "path": "/items/42",
		"status": float64(201), "bytes": float64(5), "level": "INFO",
	}
	for k, v := range checks {
		if entry[k] != v {
			t.Errorf("%s = %v, want %v", k, entry[k], v)
		}
	}
	if entry["request_id"] == nil || entry["client_ip"] == nil {
		t.Errorf("missing request_id or client_ip: %v", entry)
	}
	if ua, _ := entry["user_agent"].(string); len(ua) != maxLoggedUserAgentLength {
		t.Errorf("user agent not truncated: len %d", len(ua))
	}
	if strings.Contains(lines[0], "secret") {
		t.Error("query string must not be logged")
	}
	if !strings.Contains(lines[1], `"level":"ERROR"`) {
		t.Errorf("5xx should log at error level: %s", lines[1])
	}
}

func TestHTTPMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m, err := NewHTTPMetrics(reg)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(m.Middleware())
	e.GET("/items/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/items/1", http.NoBody))
	serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/items/2", http.NoBody))
	serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/nope/123", http.NoBody))
	serve(e, httptest.NewRequestWithContext(context.Background(), "BREW", "/items/1", http.NoBody))

	if got := testutil.ToFloat64(m.requests.WithLabelValues("GET", "/items/:id", "200")); got != 2 {
		t.Errorf("route counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("GET", unmatchedRoute, "404")); got != 1 {
		t.Errorf("unmatched counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("OTHER", unmatchedRoute, "404")); got != 1 {
		t.Errorf("non-standard method counter = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.duration); got != 3 {
		t.Errorf("histogram series = %d, want 3", got)
	}
	if got := testutil.ToFloat64(m.inFlight); got != 0 {
		t.Errorf("in-flight = %v after all requests finished", got)
	}

	if _, err := NewHTTPMetrics(reg); err == nil {
		t.Error("registering twice should fail")
	}
}

func TestAbortWithErrorWithoutRequestID(t *testing.T) {
	e := newEngine()
	e.GET("/", func(c *gin.Context) { AbortWithError(c, http.StatusForbidden, "forbidden", "no") })
	rec := serve(e, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "request_id") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
