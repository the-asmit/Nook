//go:build integration

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"html"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/gateway"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/logging"
)

// startGateway runs a gateway on the fixed gateway port (the one Dex
// knows) against the env's primary instance, until the test ends.
func (e *env) startGateway(overrides map[string]string) {
	t := e.t
	t.Helper()
	environ := map[string]string{
		"NOOK_ENV":                       "development",
		"NOOK_LOG_LEVEL":                 "debug",
		"NOOK_REDIS_URL":                 shared.redisURL,
		"NOOK_APPS_BASE_URL":             appsBaseURL(),
		"NOOK_GATEWAY_CONTROL_PLANE_URL": e.base,
		"NOOK_GATEWAY_SECRET":            testGatewaySecret,
		"NOOK_GATEWAY_TLS_MODE":          "off",
		"NOOK_GATEWAY_HTTP_ADDR":         "127.0.0.1:" + strconv.Itoa(shared.gatewayPort),
		"NOOK_GATEWAY_OPS_ADDR":          "127.0.0.1:0",
		"NOOK_GATEWAY_RESYNC_INTERVAL":   "2s",
		"NOOK_GATEWAY_ACCESS_CACHE_TTL":  "2s",
		"NOOK_GATEWAY_DRAIN_TIMEOUT":     "2s",
	}
	maps.Copy(environ, overrides)
	cfg, err := config.Load[gateway.Config](environ)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger, err := logging.New(logs, cfg.Log)
	if err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(context.Background(), &cfg, logger)
	if err != nil {
		t.Fatalf("gateway.New() = %v\nlogs:\n%s", err, logs.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("gateway Serve() = %v", err)
			}
			g.Close()
		})
	}
	t.Cleanup(stop)
}

// appOrigin is an app's origin on the test gateway.
func appOrigin(ws, app string) string {
	return "http://" + app + "--" + ws + ".apps.localhost:" + strconv.Itoa(shared.gatewayPort)
}

// localhostDialer resolves *.localhost to 127.0.0.1, as browsers do.
func localhostDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		addr = net.JoinHostPort("127.0.0.1", port)
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

// appVisitor is a browser visiting apps through the gateway.
type appVisitor struct {
	t   *testing.T
	jar *cookiejar.Jar
	c   *http.Client
}

func newVisitor(t *testing.T) *appVisitor {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &appVisitor{t: t, jar: jar, c: &http.Client{
		Jar: jar, Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: localhostDialer, DisableKeepAlives: true},
	}}
}

// get fetches a URL, following redirects.
func (v *appVisitor) get(target string) response {
	v.t.Helper()
	return send(v.t, v.c, newRequest(v.t, http.MethodGet, target, http.NoBody))
}

// noFollow fetches a URL without following redirects.
func (v *appVisitor) noFollow(target string, header http.Header) response {
	v.t.Helper()
	c := *v.c
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req := newRequest(v.t, http.MethodGet, target, http.NoBody)
	maps.Copy(req.Header, header)
	return send(v.t, &c, req)
}

// signInAt opens target (an app URL); when the gateway sends the visitor
// to sign in, they sign in at Dex as email. It returns the final response.
func (v *appVisitor) signInAt(target, email string) response {
	v.t.Helper()
	r := v.get(target)
	m := formAction.FindStringSubmatch(r.body)
	if m == nil {
		return r // already signed in (or no sign-in needed)
	}
	action, err := r.url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		v.t.Fatal(err)
	}
	form := url.Values{"login": {email}, "password": {shared.dex.Passwords[email]}}
	req := newRequest(v.t, http.MethodPost, action.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return send(v.t, v.c, req)
}

// cookie returns the named cookie the jar holds for origin.
func (v *appVisitor) cookie(origin, name string) string {
	u, err := url.Parse(origin)
	if err != nil {
		v.t.Fatal(err)
	}
	for _, c := range v.jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// seen is what the test app reports from /headers.
type seen struct {
	Host    string              `json:"host"`
	Headers map[string][]string `json:"headers"`
}

func (s seen) header(name string) string {
	return strings.Join(s.Headers[http.CanonicalHeaderKey(name)], ", ")
}

func parseSeen(t *testing.T, r response) seen {
	t.Helper()
	var s seen
	if r.status != http.StatusOK {
		t.Fatalf("GET %s: %d %.400s", r.url, r.status, r.body)
	}
	if err := json.Unmarshal([]byte(r.body), &s); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
	return s
}

// dialUpgrade asks the gateway to upgrade path on host (a WebSocket) and
// returns the connection, a reader for what follows the response, and the
// response status.
func dialUpgrade(t *testing.T, host, path string, header http.Header) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := localhostDialer(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(shared.gatewayPort)))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + host + ":" + strconv.Itoa(shared.gatewayPort) + "\r\n")
	b.WriteString("Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	for k, vs := range header {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	if _, werr := io.WriteString(conn, b.String()); werr != nil {
		t.Fatal(werr)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	_ = resp.Body.Close()
	return conn, br, resp.StatusCode
}
