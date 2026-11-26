package gateway

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/routes"
)

func TestLimiterRefills(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLimiter(2, 3)
	l.now = func() time.Time { return now }
	for i := range 3 {
		if !l.allow("ip") {
			t.Fatalf("request %d refused within the burst", i)
		}
	}
	if l.allow("ip") {
		t.Fatal("request beyond the burst allowed")
	}
	if !l.allow("other") {
		t.Fatal("keys share a bucket")
	}
	now = now.Add(500 * time.Millisecond) // one token at 2/s
	if !l.allow("ip") || l.allow("ip") {
		t.Fatal("refill is not one token per half second")
	}
	now = now.Add(time.Hour)
	l.allow("other")
	if _, ok := l.buckets["ip"]; ok {
		t.Fatal("an idle bucket was not swept")
	}
}

func TestAccessCacheKeepsOnlyDecisions(t *testing.T) {
	c := newAccessCache(time.Minute)
	calls := 0
	status := "invalid"
	check := func(context.Context, string, string) (checked, error) {
		calls++
		return checked{Status: status}, nil
	}
	for range 2 {
		if _, _, err := c.get(t.Context(), "tok", "a", check); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("invalid sessions were cached (%d calls)", calls)
	}
	status = "ok"
	for range 2 {
		if _, _, err := c.get(t.Context(), "tok", "a", check); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want the ok decision cached", calls)
	}
	// Bound to the host.
	if _, cached, _ := c.get(t.Context(), "tok", "b", check); cached {
		t.Fatal("a decision for host a answered for host b")
	}
	c.forget("tok", "a")
	if _, cached, _ := c.get(t.Context(), "tok", "a", check); cached {
		t.Fatal("forget did not drop the decision")
	}
	failing := func(context.Context, string, string) (checked, error) { return checked{}, errors.New("down") }
	if _, _, err := c.get(t.Context(), "new", "a", failing); err == nil {
		t.Fatal("a failed check was not reported")
	}
}

func TestHostPolicyRefusesUnknownHosts(t *testing.T) {
	f := newFixture(t, nil)
	r := f.addApp("tool", routes.AccessWorkspace, routes.StateRunning, "")
	f.cp.mu.Lock()
	f.cp.known["fresh--ws.apps.localhost"] = true
	f.cp.mu.Unlock()
	policy := hostPolicy(f.h.authHost, f.table, f.h.cp.knownHost)
	for host, want := range map[string]error{
		"auth.apps.localhost":      nil,
		r.Host:                     nil,
		"TOOL--WS.apps.localhost":  nil,
		"fresh--ws.apps.localhost": nil, // not in the table yet, known upstream
		"random.example.com":       errUnknownHost,
		"nope--ws.apps.localhost":  errUnknownHost,
	} {
		if err := policy(t.Context(), host); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", host, err, want)
		}
	}
	f.cp.srv.Close()
	if err := policy(t.Context(), "other--ws.apps.localhost"); err == nil {
		t.Error("an unreachable control plane allowed a certificate")
	}
}

func TestTableRefreshAndResync(t *testing.T) {
	f := newFixture(t, nil)
	a := f.addApp("a", routes.AccessWorkspace, routes.StateRunning, "10.0.0.1:1000")
	if got, ok := f.table.lookup(a.Host); !ok || got.Upstream != "10.0.0.1:1000" {
		t.Fatalf("lookup = %+v %v", got, ok)
	}
	// The app moves: a refresh picks up the new upstream.
	a.Upstream = "10.0.0.2:2000"
	f.cp.set(&a)
	if err := f.table.refresh(t.Context(), a.AppID); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.table.lookup(a.Host); got.Upstream != "10.0.0.2:2000" {
		t.Fatalf("after refresh upstream = %q", got.Upstream)
	}
	// Deleted: a refresh removes it.
	f.cp.remove(a.AppID)
	if err := f.table.refresh(t.Context(), a.AppID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.table.lookup(a.Host); ok {
		t.Fatal("a deleted app is still routed")
	}
	// A failed resync keeps the last known table.
	b := routes.Route{AppID: uuid.NewV7(), Host: "b--ws.apps.localhost", Access: routes.AccessPublic, State: routes.StateRunning}
	f.cp.set(&b)
	if err := f.table.resync(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.cp.mu.Lock()
	f.cp.failNext = true
	f.cp.mu.Unlock()
	if err := f.table.resync(t.Context()); err == nil {
		t.Fatal("resync against a failing control plane succeeded")
	}
	if _, ok := f.table.lookup(b.Host); !ok {
		t.Fatal("a failed resync dropped the table")
	}
}

// devEnviron is a valid development environment for the gateway.
func devEnviron() map[string]string {
	return map[string]string{
		"NOOK_ENV":                       "development",
		"NOOK_REDIS_URL":                 "redis://127.0.0.1:6379/0",
		"NOOK_APPS_BASE_URL":             "http://apps.localhost:8090",
		"NOOK_GATEWAY_CONTROL_PLANE_URL": "http://127.0.0.1:8080",
		"NOOK_GATEWAY_SECRET":            testSecret,
		"NOOK_GATEWAY_TLS_MODE":          "off",
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := config.Load[Config](devEnviron()); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	prod := map[string]string{
		"NOOK_ENV": "production", "NOOK_REDIS_URL": "rediss://redis.internal:6379/0",
		"NOOK_APPS_BASE_URL": "https://apps.example.com", "NOOK_GATEWAY_TLS_MODE": "proxy",
		"NOOK_GATEWAY_TRUSTED_PROXIES": "10.0.0.0/8", "NOOK_GATEWAY_CONTROL_PLANE_URL": "http://10.0.0.5:8080",
		"NOOK_ALLOW_PLAINTEXT_INTERNAL": "true",
	}
	for name, change := range map[string]map[string]string{
		"off outside development":    {"NOOK_ENV": "production"},
		"off on a real domain":       {"NOOK_APPS_BASE_URL": "http://apps.example.com"},
		"short secret":               {"NOOK_GATEWAY_SECRET": "short"},
		"acme without email":         {"NOOK_GATEWAY_TLS_MODE": "acme", "NOOK_APPS_BASE_URL": "https://apps.example.com"},
		"acme on http":               {"NOOK_GATEWAY_TLS_MODE": "acme", "NOOK_GATEWAY_ACME_EMAIL": "ops@example.com"},
		"files without paths":        {"NOOK_GATEWAY_TLS_MODE": "files", "NOOK_APPS_BASE_URL": "https://apps.example.com"},
		"proxy without proxies":      {"NOOK_GATEWAY_TLS_MODE": "proxy", "NOOK_APPS_BASE_URL": "https://apps.example.com"},
		"bad proxy":                  {"NOOK_GATEWAY_TLS_MODE": "proxy", "NOOK_APPS_BASE_URL": "https://apps.example.com", "NOOK_GATEWAY_TRUSTED_PROXIES": "nope"},
		"unknown mode":               {"NOOK_GATEWAY_TLS_MODE": "magic"},
		"bad control plane URL":      {"NOOK_GATEWAY_CONTROL_PLANE_URL": "ftp://cp"},
		"plaintext cp in production": {"NOOK_ALLOW_PLAINTEXT_INTERNAL": "false"},
	} {
		environ := devEnviron()
		if name == "plaintext cp in production" {
			environ = maps.Clone(prod)
		}
		maps.Copy(environ, change)
		environ["NOOK_GATEWAY_SECRET"] = cmp.Or(change["NOOK_GATEWAY_SECRET"], testSecret)
		if _, err := config.Load[Config](environ); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	prod["NOOK_GATEWAY_SECRET"] = testSecret
	if _, err := config.Load[Config](prod); err != nil {
		t.Fatalf("proxy mode with an internal control plane: %v", err)
	}
}

func TestHTTPRedirectsOnlyKnownHostsToHTTPS(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.AppsBaseURL = "https://apps.example.com" })
	r := routes.Route{AppID: uuid.NewV7(), Host: "tool--ws.apps.example.com", Access: routes.AccessWorkspace, State: routes.StateRunning}
	f.cp.set(&r)
	if err := f.table.resync(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, path, method string
		status             int
		location           string
	}{
		{"TOOL--ws.apps.example.com", "/a?b=1", http.MethodGet, http.StatusPermanentRedirect, "https://tool--ws.apps.example.com/a?b=1"},
		{"auth.apps.example.com", "/start", http.MethodGet, http.StatusPermanentRedirect, "https://auth.apps.example.com/start"},
		{"evil.test", "/", http.MethodGet, http.StatusNotFound, ""},
		{"tool--ws.apps.example.com", "/", http.MethodPost, http.StatusBadRequest, ""},
	} {
		req := httptest.NewRequestWithContext(t.Context(), tc.method, "http://"+tc.host+tc.path, http.NoBody)
		rec := httptest.NewRecorder()
		f.h.redirectToHTTPS(rec, req)
		if rec.Code != tc.status || rec.Header().Get("Location") != tc.location {
			t.Errorf("%s %s%s: %d %q", tc.method, tc.host, tc.path, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestPagesEscapeValues(t *testing.T) {
	evil := `<script>alert(1)</script>`
	rec := httptest.NewRecorder()
	page(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody), http.StatusForbidden, evil, evil, &pageLink{URL: "javascript:alert(1)", Text: evil})
	body := rec.Body.String()
	if rec.Code != http.StatusForbidden || strings.Contains(body, "<script>") || strings.Contains(body, `href="javascript:`) {
		t.Fatalf("unescaped page:\n%s", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", rec.Header())
	}
}
