package gateway

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/routes"
)

const testSecret = "gateway-test-secret-0123456789abcdef"

// fakeCP is the control plane's internal API with in-memory state.
type fakeCP struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	routes   map[uuid.UUID]routes.Route
	sessions map[string]fakeSession // token → session
	codes    map[string]fakeCode    // code → pending sign-in
	known    map[string]bool        // hosts for the TLS check
	checks   int
	failNext bool
}

type fakeSession struct {
	host, email string
	denied      bool
}

type fakeCode struct {
	host, token, returnPath string
}

func newFakeCP(t *testing.T) *fakeCP {
	t.Helper()
	f := &fakeCP{
		t: t, routes: map[uuid.UUID]routes.Route{}, sessions: map[string]fakeSession{},
		codes: map[string]fakeCode{}, known: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/routes", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failNext {
			f.failNext = false
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		list := []routes.Route{}
		for _, r := range f.routes {
			list = append(list, r)
		}
		writeJSON(w, map[string]any{"routes": list})
	})
	mux.HandleFunc("GET /internal/v1/routes/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id, err := uuid.Parse(r.PathValue("id"))
		route, ok := f.routes[id]
		if err != nil || !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, route)
	})
	mux.HandleFunc("GET /internal/v1/tls/hosts/{host}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.known[r.PathValue("host")] {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("POST /internal/v1/visitor/exchange", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Code, Host string }
		decode(t, r, &in)
		f.mu.Lock()
		defer f.mu.Unlock()
		c, ok := f.codes[in.Code]
		if !ok || c.host != in.Host {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		delete(f.codes, in.Code)
		writeJSON(w, map[string]any{"token": c.token, "expires_at": time.Now().Add(time.Hour), "return_path": c.returnPath})
	})
	mux.HandleFunc("POST /internal/v1/visitor/check", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Token, Host string }
		decode(t, r, &in)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.checks++
		s, ok := f.sessions[in.Token]
		switch {
		case !ok || s.host != in.Host:
			writeJSON(w, map[string]string{"status": "invalid"})
		case s.denied:
			writeJSON(w, map[string]string{"status": "denied", "email": s.email})
		default:
			writeJSON(w, map[string]string{"status": "ok", "email": s.email, "name": "Test\r\nVisitor"})
		}
	})
	mux.HandleFunc("POST /internal/v1/visitor/sign-out", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Token string }
		decode(t, r, &in)
		f.mu.Lock()
		delete(f.sessions, in.Token)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testSecret {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCP) set(r *routes.Route) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[r.AppID] = *r
}

func (f *fakeCP) remove(id uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.routes, id)
}

func (f *fakeCP) session(token string, s fakeSession) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[token] = s
}

func (f *fakeCP) checkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func decode(t *testing.T, r *http.Request, v any) {
	t.Helper()
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		t.Errorf("decode request: %v", err)
	}
}

// testConfig is a development configuration for apps.localhost.
func testConfig(cpURL string) *Config {
	return &Config{
		Environment:           config.Development,
		AppsBaseURL:           "http://apps.localhost:8090",
		ControlPlaneURL:       cpURL,
		Secret:                config.NewSecret(testSecret),
		TLSMode:               TLSOff,
		HTTPAddr:              "127.0.0.1:0",
		OpsAddr:               "127.0.0.1:0",
		ResyncInterval:        time.Hour,
		AccessCacheTTL:        30 * time.Second,
		MaxBodyBytes:          1 << 20,
		UpstreamHeaderTimeout: 5 * time.Second,
		RatePerIP:             1000,
		BurstPerIP:            1000,
		RatePerApp:            1000,
		BurstPerApp:           1000,
		DrainTimeout:          5 * time.Second,
	}
}

// fixture is a handler in front of a fake control plane.
type fixture struct {
	t     *testing.T
	cp    *fakeCP
	cfg   *Config
	table *table
	h     *handler
	srv   *httptest.Server
}

func newFixture(t *testing.T, adjust func(*Config)) *fixture {
	t.Helper()
	cp := newFakeCP(t)
	cfg := testConfig(cp.srv.URL)
	if adjust != nil {
		adjust(cfg)
	}
	m, err := newMetrics(prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := newControlPlane(cfg.ControlPlaneURL, testSecret)
	tbl := newTable(client, logger, m)
	h, err := newHandler(cfg, tbl, client, m, newConnTracker(), logger)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &fixture{t: t, cp: cp, cfg: cfg, table: tbl, h: h, srv: srv}
}

// addApp registers a route served by upstream (empty: not serving).
func (f *fixture) addApp(app, access, state, upstream string) routes.Route {
	f.t.Helper()
	r := routes.Route{
		AppID: uuid.NewV7(), Host: app + "--ws.apps.localhost", Workspace: "ws", App: app,
		Access: access, State: state, Upstream: upstream,
	}
	f.cp.set(&r)
	if err := f.table.resync(f.t.Context()); err != nil {
		f.t.Fatal(err)
	}
	return r
}

// result is a completed exchange with the gateway.
type result struct {
	status  int
	header  http.Header
	body    string
	cookies []*http.Cookie
}

// do sends a request for host without following redirects.
func (f *fixture) do(method, host, path string, hdr http.Header, body io.Reader) result {
	f.t.Helper()
	req, err := http.NewRequestWithContext(f.t.Context(), method, f.srv.URL+path, body)
	if err != nil {
		f.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Host = host
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return result{status: resp.StatusCode, header: resp.Header, body: string(b), cookies: resp.Cookies()}
}

// received decodes what the echo upstream answered.
func (r result) received(t *testing.T) received {
	t.Helper()
	var got received
	if err := json.Unmarshal([]byte(r.body), &got); err != nil {
		t.Fatalf("decode %d %q: %v", r.status, r.body, err)
	}
	return got
}

// echoUpstream answers with what it received as JSON.
type received struct {
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func newEchoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		writeJSON(w, received{Host: r.Host, Path: r.URL.RequestURI(), Headers: r.Header, Body: string(b)})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func hostOf(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "http://") }
