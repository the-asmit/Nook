package gateway

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/routes"
)

func TestUnknownHostIsNotFound(t *testing.T) {
	f := newFixture(t, nil)
	resp := f.do(http.MethodGet, "nope--ws.apps.localhost", "/", nil, nil)
	body := resp.body
	if resp.status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.status)
	}
	id := resp.header.Get("X-Request-ID")
	if id == "" || !strings.Contains(body, id) || !strings.Contains(body, "App not found") {
		t.Fatalf("the 404 page lacks its title or request ID %q:\n%s", id, body)
	}
	if csp := resp.header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("CSP = %q", csp)
	}
}

func TestPublicAppIsProxiedWithSanitizedHeaders(t *testing.T) {
	f := newFixture(t, nil)
	up := newEchoUpstream(t)
	r := f.addApp("site", routes.AccessPublic, routes.StateRunning, hostOf(up))
	hdr := http.Header{
		"X-Nook-Email":    {"spoofed@evil.test"},
		"X-Nook-Anything": {"x"},
		"X-Forwarded-For": {"203.0.113.9"},
		"X-Request-Id":    {"client-chosen"},
		"Cookie":          {"app=1; nook_visitor=stolen; __Host-nook_visitor=x; nook_session=y; other=2"},
	}
	resp := f.do(http.MethodPost, r.Host, "/path?q=1", hdr, strings.NewReader("hello"))
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.status, resp.body)
	}
	got := resp.received(t)
	if got.Host != r.Host || got.Path != "/path?q=1" || got.Body != "hello" {
		t.Fatalf("upstream got host=%q path=%q body=%q", got.Host, got.Path, got.Body)
	}
	for name := range got.Headers {
		if strings.HasPrefix(strings.ToLower(name), "x-nook-") {
			t.Errorf("a client's %s header reached the app", name)
		}
	}
	if c := strings.Join(got.Headers["Cookie"], "; "); c != "app=1; other=2" {
		t.Errorf("Cookie at the app = %q, want only the app's cookies", c)
	}
	if xff := got.Headers["X-Forwarded-For"]; len(xff) != 1 || xff[0] != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q: an untrusted client's value must be replaced", xff)
	}
	if p := got.Headers["X-Forwarded-Proto"]; len(p) != 1 || p[0] != "http" {
		t.Errorf("X-Forwarded-Proto = %q", p)
	}
	if h := got.Headers["X-Forwarded-Host"]; len(h) != 1 || h[0] != r.Host {
		t.Errorf("X-Forwarded-Host = %q", h)
	}
	if id := got.Headers["X-Request-Id"]; len(id) != 1 || id[0] == "client-chosen" || id[0] != resp.header.Get("X-Request-ID") {
		t.Errorf("request ID at the app = %q, response %q", id, resp.header.Get("X-Request-ID"))
	}
}

func TestTrustedProxyChainIsKept(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.TrustedProxies = []string{"127.0.0.0/8"} })
	up := newEchoUpstream(t)
	r := f.addApp("site", routes.AccessPublic, routes.StateRunning, hostOf(up))
	resp := f.do(http.MethodGet, r.Host, "/", http.Header{"X-Forwarded-For": {"198.51.100.7"}, "X-Request-Id": {"edge-123"}}, nil)
	got := resp.received(t)
	if xff := got.Headers["X-Forwarded-For"]; len(xff) != 1 || xff[0] != "198.51.100.7, 127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q", xff)
	}
	if id := got.Headers["X-Request-Id"]; len(id) != 1 || id[0] != "edge-123" {
		t.Errorf("request ID from a trusted proxy = %q", id)
	}
}

func TestPrivateAppRedirectsToTheAuthHost(t *testing.T) {
	f := newFixture(t, nil)
	up := newEchoUpstream(t)
	r := f.addApp("tool", routes.AccessWorkspace, routes.StateRunning, hostOf(up))

	resp := f.do(http.MethodGet, r.Host, "/reports?x=1", nil, nil)
	if resp.status != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.status)
	}
	loc, err := url.Parse(resp.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "auth.apps.localhost:8090" || loc.Path != "/start" ||
		loc.Query().Get("app") != r.Host || loc.Query().Get("return") != "/reports?x=1" {
		t.Fatalf("redirect = %s", loc)
	}
	// A state change without a session is refused, not redirected.
	if post := f.do(http.MethodPost, r.Host, "/", nil, nil); post.status != http.StatusUnauthorized {
		t.Fatalf("POST status = %d, want 401", post.status)
	}
	// A session for another host is not a session here.
	f.cp.session("tok-other", fakeSession{host: "other--ws.apps.localhost", email: "a@nook.test"})
	resp = f.do(http.MethodGet, r.Host, "/", http.Header{"Cookie": {"nook_visitor=tok-other"}}, nil)
	if resp.status != http.StatusFound {
		t.Fatalf("another app's cookie: status = %d, want a sign-in redirect", resp.status)
	}
}

func TestSignedInVisitorReachesTheApp(t *testing.T) {
	f := newFixture(t, nil)
	up := newEchoUpstream(t)
	r := f.addApp("tool", routes.AccessRestricted, routes.StateRunning, hostOf(up))
	f.cp.mu.Lock()
	f.cp.codes["code-1"] = fakeCode{host: r.Host, token: "tok-1", returnPath: "/deep/link?a=b"}
	f.cp.mu.Unlock()
	f.cp.session("tok-1", fakeSession{host: r.Host, email: "alice@nook.test"})

	// The code is bound to its host: another app cannot redeem it.
	other := f.addApp("other", routes.AccessWorkspace, routes.StateRunning, hostOf(up))
	if resp := f.do(http.MethodGet, other.Host, "/_nook/callback?code=code-1", nil, nil); resp.status != http.StatusBadRequest {
		t.Fatalf("code on another host: status = %d, want 400", resp.status)
	}

	resp := f.do(http.MethodGet, r.Host, "/_nook/callback?code=code-1", nil, nil)
	if resp.status != http.StatusSeeOther || resp.header.Get("Location") != "/deep/link?a=b" {
		t.Fatalf("callback: status %d, Location %q", resp.status, resp.header.Get("Location"))
	}
	var cookie *http.Cookie
	for _, c := range resp.cookies {
		if c.Name == "nook_visitor" {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value != "tok-1" || !cookie.HttpOnly || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
		t.Fatalf("session cookie = %+v, want host-only, HttpOnly, SameSite=Lax", cookie)
	}
	// Single use.
	if again := f.do(http.MethodGet, r.Host, "/_nook/callback?code=code-1", nil, nil); again.status != http.StatusBadRequest {
		t.Fatalf("second use: status = %d, want 400", again.status)
	}

	resp = f.do(http.MethodGet, r.Host, "/", http.Header{"Cookie": {"nook_visitor=tok-1"}, "X-Nook-Email": {"mallory@evil.test"}}, nil)
	got := resp.received(t)
	if e := got.Headers["X-Nook-Email"]; len(e) != 1 || e[0] != "alice@nook.test" {
		t.Fatalf("X-Nook-Email = %q", e)
	}
	if n := got.Headers["X-Nook-Name"]; len(n) != 1 || n[0] != "TestVisitor" {
		t.Fatalf("X-Nook-Name = %q, want control characters removed", n)
	}
	if _, ok := got.Headers["Cookie"]; ok {
		t.Fatalf("the visitor cookie reached the app: %q", got.Headers["Cookie"])
	}
}

func TestDeniedVisitorGetsForbidden(t *testing.T) {
	f := newFixture(t, nil)
	up := newEchoUpstream(t)
	r := f.addApp("tool", routes.AccessRestricted, routes.StateRunning, hostOf(up))
	f.cp.session("tok-bob", fakeSession{host: r.Host, email: "bob@partner.test", denied: true})
	resp := f.do(http.MethodGet, r.Host, "/", http.Header{"Cookie": {"nook_visitor=tok-bob"}}, nil)
	body := resp.body
	if resp.status != http.StatusForbidden || !strings.Contains(body, "bob@partner.test") || !strings.Contains(body, "/_nook/sign-out") {
		t.Fatalf("status %d:\n%s", resp.status, body)
	}
}

func TestAccessDecisionsAreCachedBriefly(t *testing.T) {
	f := newFixture(t, nil)
	up := newEchoUpstream(t)
	r := f.addApp("tool", routes.AccessWorkspace, routes.StateRunning, hostOf(up))
	now := time.Now()
	f.h.cache.now = func() time.Time { return now }
	f.cp.session("tok", fakeSession{host: r.Host, email: "alice@nook.test"})
	cookie := http.Header{"Cookie": {"nook_visitor=tok"}}
	for range 3 {
		if resp := f.do(http.MethodGet, r.Host, "/", cookie, nil); resp.status != http.StatusOK {
			t.Fatalf("status = %d", resp.status)
		}
	}
	if n := f.cp.checkCount(); n != 1 {
		t.Fatalf("control plane asked %d times within the cache window, want 1", n)
	}
	// Access revoked: the cached decision holds until the window ends.
	f.cp.session("tok", fakeSession{host: r.Host, email: "alice@nook.test", denied: true})
	if resp := f.do(http.MethodGet, r.Host, "/", cookie, nil); resp.status != http.StatusOK {
		t.Fatalf("within the window: status = %d", resp.status)
	}
	now = now.Add(f.cfg.AccessCacheTTL + time.Second)
	if resp := f.do(http.MethodGet, r.Host, "/", cookie, nil); resp.status != http.StatusForbidden {
		t.Fatalf("after the window: status = %d, want 403", resp.status)
	}
}

func TestSignOutClearsTheSession(t *testing.T) {
	f := newFixture(t, nil)
	r := f.addApp("tool", routes.AccessWorkspace, routes.StateRunning, "127.0.0.1:1")
	f.cp.session("tok", fakeSession{host: r.Host, email: "alice@nook.test"})
	resp := f.do(http.MethodGet, r.Host, "/_nook/sign-out", http.Header{"Cookie": {"nook_visitor=tok"}}, nil)
	if resp.status != http.StatusSeeOther || resp.header.Get("Location") != "http://auth.apps.localhost:8090/sign-out" {
		t.Fatalf("status %d, Location %q", resp.status, resp.header.Get("Location"))
	}
	cleared := false
	for _, c := range resp.cookies {
		cleared = cleared || (c.Name == "nook_visitor" && c.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("the session cookie was not cleared")
	}
	f.cp.mu.Lock()
	_, still := f.cp.sessions["tok"]
	f.cp.mu.Unlock()
	if still {
		t.Fatal("the session was not revoked on the control plane")
	}
}

func TestReservedPathsNeverReachTheApp(t *testing.T) {
	f := newFixture(t, nil)
	up := newEchoUpstream(t)
	r := f.addApp("site", routes.AccessPublic, routes.StateRunning, hostOf(up))
	for _, p := range []string{"/_nook", "/_nook/", "/_nook/anything", "/_nook/callback/x"} {
		resp := f.do(http.MethodGet, r.Host, p, nil, nil)
		if resp.status != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", p, resp.status)
		}
	}
}

func TestUnavailableAndUnreachableApps(t *testing.T) {
	f := newFixture(t, nil)
	stopped := f.addApp("stopped", routes.AccessPublic, routes.StateStopped, "")
	crashed := f.addApp("crashed", routes.AccessPublic, routes.StateCrashed, "")
	// A listener that is closed at once: nothing answers there.
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	gone := f.addApp("gone", routes.AccessPublic, routes.StateRunning, dead)

	for _, tc := range []struct {
		host   string
		status int
		text   string
	}{
		{stopped.Host, http.StatusServiceUnavailable, routes.Describe(routes.StateStopped)},
		{crashed.Host, http.StatusServiceUnavailable, routes.Describe(routes.StateCrashed)},
		{gone.Host, http.StatusBadGateway, "App unreachable"},
	} {
		resp := f.do(http.MethodGet, tc.host, "/", nil, nil)
		body := resp.body
		if resp.status != tc.status || !strings.Contains(body, tc.text) || !strings.Contains(body, resp.header.Get("X-Request-ID")) {
			t.Errorf("%s: status %d, want %d with %q:\n%s", tc.host, resp.status, tc.status, tc.text, body)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxBodyBytes = 1024 })
	up := newEchoUpstream(t)
	r := f.addApp("site", routes.AccessPublic, routes.StateRunning, hostOf(up))
	resp := f.do(http.MethodPost, r.Host, "/", nil, strings.NewReader(strings.Repeat("x", 4096)))
	if resp.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.status)
	}
}

func TestRateLimitPerIP(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RatePerIP, c.BurstPerIP = 0.1, 2 })
	for i, want := range []int{http.StatusNotFound, http.StatusNotFound, http.StatusTooManyRequests} {
		if resp := f.do(http.MethodGet, "x--ws.apps.localhost", "/", nil, nil); resp.status != want {
			t.Fatalf("request %d: status = %d, want %d", i, resp.status, want)
		}
	}
}

func TestStreamingResponsesAreFlushed(t *testing.T) {
	f := newFixture(t, nil)
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		_ = http.NewResponseController(w).Flush()
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
	}))
	t.Cleanup(up.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	r := f.addApp("events", routes.AccessPublic, routes.StateRunning, hostOf(up))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+"/stream", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = r.Host
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Body.Close() }()
	br := bufio.NewReader(stream.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("first event = %q, %v (it must arrive before the stream ends)", line, err)
	}
	close(release)
	rest, err := io.ReadAll(br)
	if err != nil || !strings.Contains(string(rest), "data: second") {
		t.Fatalf("rest = %q, %v", rest, err)
	}
}

func TestWebSocketUpgradePassesThrough(t *testing.T) {
	f := newFixture(t, nil)
	up := newUpgradeEcho(t)
	r := f.addApp("ws", routes.AccessPublic, routes.StateRunning, hostOf(up))
	conn := dialUpgrade(t, hostOf(f.srv), r.Host)
	defer func() { _ = conn.Close() }()
	echo(t, conn, "ping through the gateway")
	if n := gaugeValue(t, f.h.m.upgraded); n != 1 {
		t.Fatalf("upgraded connections gauge = %v, want 1", n)
	}
}

func TestReturnPathsStayOnTheHost(t *testing.T) {
	f := newFixture(t, nil)
	r := f.addApp("tool", routes.AccessWorkspace, routes.StateRunning, "127.0.0.1:1")
	f.cp.mu.Lock()
	f.cp.codes["c"] = fakeCode{host: r.Host, token: "t", returnPath: "//evil.test/x"}
	f.cp.mu.Unlock()
	resp := f.do(http.MethodGet, r.Host, "/_nook/callback?code=c", nil, nil)
	if loc := resp.header.Get("Location"); loc != "/" {
		t.Fatalf("Location = %q, want / for a protocol-relative return path", loc)
	}
}
