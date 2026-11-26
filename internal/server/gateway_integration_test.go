//go:build integration

package server

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/testinfra"
)

// accessCacheTTL is the test gateway's NOOK_GATEWAY_ACCESS_CACHE_TTL.
const accessCacheTTL = 2 * time.Second

// TestVisitorsThroughTheGateway runs one app on a real node behind a real
// gateway and signs visitors in through Dex: members get in, outsiders
// only when granted, revocations apply within the access cache window,
// public apps need no sign-in, and the app sees the visitor's identity in
// headers no client can forge.
func TestVisitorsThroughTheGateway(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	alice := r.alice
	expectStatus(t, r.as(alice, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Acme", "slug": "acme"}), 201, "create workspace")
	expectStatus(t, r.as(alice, http.MethodPost, "/api/v1/workspaces/acme/invitations", map[string]string{"email": testinfra.DexBob, "role": "member"}), 201, "invite bob")
	if res := r.browser().signIn(testinfra.DexBob); res.status != http.StatusOK {
		t.Fatalf("bob's Nook sign-in: %d", res.status)
	}
	r.newRuntimeApp(alice, "acme", "tool", nil)
	r.newRuntimeApp(alice, "acme", "other", nil) // never deployed
	r.waitLive(alice, "acme", "tool", r.release("acme", "tool"))
	r.startGateway(nil)

	tool, other := appOrigin("acme", "tool"), appOrigin("acme", "other")
	const toolHost = "tool--acme.apps.localhost"
	authOrigin := "http://auth.apps.localhost:" + strconv.Itoa(shared.gatewayPort)
	access := appURL("acme", "tool") + "/access"

	t.Run("the API reports the URL and the default policy", func(t *testing.T) {
		res := r.as(alice, http.MethodGet, appURL("acme", "tool"), nil)
		if !strings.Contains(res.body, `"url":"`+tool+`/"`) || !strings.Contains(res.body, `"access_mode":"workspace"`) {
			t.Fatalf("app: %s", res.body)
		}
	})

	t.Run("unknown hosts get a 404 page", func(t *testing.T) {
		res := newVisitor(t).get(appOrigin("acme", "nope") + "/")
		if res.status != http.StatusNotFound || !strings.Contains(res.body, "App not found") || !strings.Contains(res.body, res.header.Get("X-Request-ID")) {
			t.Fatalf("%d %s", res.status, res.body)
		}
	})

	t.Run("visitors without a session are sent to the auth host", func(t *testing.T) {
		res := newVisitor(t).noFollow(tool+"/headers?x=1", nil)
		loc, err := url.Parse(res.header.Get("Location"))
		if err != nil || res.status != http.StatusFound || loc.Scheme+"://"+loc.Host != authOrigin || loc.Path != "/start" ||
			loc.Query().Get("app") != toolHost || loc.Query().Get("return") != "/headers?x=1" {
			t.Fatalf("%d Location %q", res.status, res.header.Get("Location"))
		}
	})

	aliceV := newVisitor(t)
	t.Run("a workspace member signs in and the app sees who", func(t *testing.T) {
		res := aliceV.signInAt(tool+"/headers?x=1", testinfra.DexAlice)
		s := parseSeen(t, res)
		if res.url.String() != tool+"/headers?x=1" {
			t.Fatalf("landed on %s, want the page asked for", res.url)
		}
		if s.header("X-Nook-Email") != testinfra.DexAlice {
			t.Fatalf("X-Nook-Email = %q", s.header("X-Nook-Email"))
		}
		if s.header("X-Forwarded-Proto") != "http" || s.header("X-Forwarded-Host") != toolHost+":"+strconv.Itoa(shared.gatewayPort) {
			t.Fatalf("forwarded headers: %+v", s.Headers)
		}
		// A forged identity header and the gateway's cookie never reach the app;
		// the app's own cookies do.
		u, _ := url.Parse(tool)
		aliceV.jar.SetCookies(u, []*http.Cookie{{Name: "app_pref", Value: "dark", Path: "/"}})
		req := newRequest(t, http.MethodGet, tool+"/headers", http.NoBody)
		req.Header.Set("X-Nook-Email", "mallory@outside.test")
		req.Header.Set("X-Nook-Role", "owner")
		s = parseSeen(t, send(t, aliceV.c, req))
		if s.header("X-Nook-Email") != testinfra.DexAlice || s.header("X-Nook-Role") != "" {
			t.Fatalf("forged headers reached the app: %+v", s.Headers)
		}
		if c := s.header("Cookie"); c != "app_pref=dark" {
			t.Fatalf("Cookie at the app = %q", c)
		}
		// Sessions are stored as hashes, bound to their host.
		token := aliceV.cookie(tool, "nook_visitor")
		sum := sha256.Sum256([]byte(token))
		if token == "" || r.count("SELECT count(*) FROM visitor_sessions WHERE token_hash = $1 AND host = $2", sum[:], toolHost) != 1 {
			t.Fatal("no hashed, host-bound session for the app host")
		}
	})

	t.Run("a session for one app is useless on another", func(t *testing.T) {
		for _, token := range []string{aliceV.cookie(tool, "nook_visitor"), aliceV.cookie(authOrigin, "nook_visitor_auth")} {
			res := newVisitor(t).noFollow(other+"/", http.Header{"Cookie": {"nook_visitor=" + token}})
			if res.status != http.StatusFound {
				t.Fatalf("status %d: another host's session was accepted", res.status)
			}
		}
		res := newVisitor(t).noFollow(tool+"/", http.Header{"Cookie": {"nook_visitor=" + aliceV.cookie(authOrigin, "nook_visitor_auth")}})
		if res.status != http.StatusFound {
			t.Fatalf("the auth host's session was accepted on an app host: %d", res.status)
		}
	})

	t.Run("sign-in codes are single-use, host-bound and short-lived", func(t *testing.T) {
		code := func() string {
			t.Helper()
			c := *aliceV.c
			c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
				if req.URL.Path == "/_nook/callback" {
					return http.ErrUseLastResponse
				}
				return nil
			}
			res := send(t, &c, newRequest(t, http.MethodGet, authOrigin+"/start?app="+url.QueryEscape(toolHost)+"&return=/", http.NoBody))
			loc, err := url.Parse(res.header.Get("Location"))
			if err != nil || res.status != http.StatusFound || loc.Path != "/_nook/callback" {
				t.Fatalf("no callback redirect: %d %q", res.status, res.header.Get("Location"))
			}
			return loc.Query().Get("code")
		}
		callback := func(origin, code string) int {
			t.Helper()
			return newVisitor(t).noFollow(origin+"/_nook/callback?code="+url.QueryEscape(code), nil).status
		}
		c := code()
		if got := callback(other, c); got != http.StatusBadRequest {
			t.Fatalf("code on another app host: %d", got)
		}
		if got := callback(tool, c); got != http.StatusSeeOther {
			t.Fatalf("code on its own host: %d", got)
		}
		if got := callback(tool, c); got != http.StatusBadRequest {
			t.Fatalf("code reused: %d", got)
		}
		c = code()
		r.exec("UPDATE visitor_codes SET expires_at = now() - interval '1 second' WHERE used_at IS NULL")
		if got := callback(tool, c); got != http.StatusBadRequest {
			t.Fatalf("expired code: %d", got)
		}
		if r.count("SELECT count(*) FROM visitor_codes WHERE code_hash = $1", []byte(c)) != 0 {
			t.Fatal("a code is stored in plain form")
		}
	})

	t.Run("return paths cannot leave the app", func(t *testing.T) {
		for _, ret := range []string{"https://evil.test/x", "//evil.test/x", `/\evil.test`, "javascript:alert(1)"} {
			res := aliceV.get(authOrigin + "/start?app=" + url.QueryEscape(toolHost) + "&return=" + url.QueryEscape(ret))
			if res.url.Host != toolHost+":"+strconv.Itoa(shared.gatewayPort) || res.url.Path != "/" {
				t.Errorf("return %q ended at %s", ret, res.url)
			}
		}
		for _, app := range []string{"evil.test", "auth.apps.localhost", "nope--acme.apps.localhost"} {
			if res := aliceV.noFollow(authOrigin+"/start?app="+url.QueryEscape(app)+"&return=/", nil); res.status != http.StatusNotFound {
				t.Errorf("start for %q: %d, want 404", app, res.status)
			}
		}
	})

	bobV, malloryV := newVisitor(t), newVisitor(t)
	t.Run("members are allowed, outsiders denied", func(t *testing.T) {
		if s := parseSeen(t, bobV.signInAt(tool+"/headers", testinfra.DexBob)); s.header("X-Nook-Email") != testinfra.DexBob {
			t.Fatalf("bob: %+v", s.Headers)
		}
		res := malloryV.signInAt(tool+"/headers", testinfra.DexMallory)
		if res.status != http.StatusForbidden || !strings.Contains(res.body, testinfra.DexMallory) {
			t.Fatalf("mallory: %d %.300s", res.status, res.body)
		}
	})

	t.Run("a granted outsider gets in; revoking applies within the cache window", func(t *testing.T) {
		expectStatus(t, r.as(alice, http.MethodPost, access+"/grants", map[string]any{"emails": []string{"Mallory@Outside.test"}}), 200, "grant")
		if s := parseSeen(t, malloryV.get(tool+"/headers")); s.header("X-Nook-Email") != testinfra.DexMallory {
			t.Fatalf("granted mallory: %+v", s.Headers)
		}
		expectStatus(t, r.as(alice, http.MethodDelete, access+"/grants/"+url.PathEscape(testinfra.DexMallory), nil), 200, "revoke")
		revoked := time.Now()
		eventually(t, accessCacheTTL+3*time.Second, "the revoked grant to be refused", func() bool {
			return malloryV.get(tool+"/headers").status == http.StatusForbidden
		})
		if d := time.Since(revoked); d > accessCacheTTL+time.Second {
			t.Fatalf("revocation took %v with a %v cache", d, accessCacheTTL)
		}
	})

	t.Run("restricted mode admits admins and grants only", func(t *testing.T) {
		expectStatus(t, r.as(alice, http.MethodPut, access, map[string]string{"mode": "restricted"}), 200, "restricted")
		eventually(t, accessCacheTTL+3*time.Second, "bob to be refused", func() bool {
			return bobV.get(tool+"/headers").status == http.StatusForbidden
		})
		if res := aliceV.get(tool + "/headers"); res.status != http.StatusOK {
			t.Fatalf("alice (owner) in restricted mode: %d", res.status)
		}
		expectStatus(t, r.as(alice, http.MethodPost, access+"/grants", map[string]any{"emails": []string{testinfra.DexBob}}), 200, "grant bob")
		eventually(t, accessCacheTTL+3*time.Second, "bob to be let in by his grant", func() bool {
			return bobV.get(tool+"/headers").status == http.StatusOK
		})
	})

	t.Run("public apps need no sign-in and carry no identity", func(t *testing.T) {
		expectStatus(t, r.as(alice, http.MethodPut, access, map[string]string{"mode": "public"}), 200, "public")
		anon := newVisitor(t)
		eventually(t, 5*time.Second, "the public route", func() bool { return anon.get(tool+"/headers").status == http.StatusOK })
		req := newRequest(t, http.MethodGet, tool+"/headers", http.NoBody)
		req.Header.Set("X-Nook-Email", "forged@evil.test")
		if s := parseSeen(t, send(t, anon.c, req)); s.header("X-Nook-Email") != "" {
			t.Fatalf("identity header on a public app: %+v", s.Headers)
		}
	})

	t.Run("WebSockets and server-sent events pass through", func(t *testing.T) {
		host := toolHost
		conn, br, status := dialUpgrade(t, host, "/ws", nil)
		defer func() { _ = conn.Close() }()
		if status != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade: %d", status)
		}
		if _, err := io.WriteString(conn, "echo through the gateway"); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len("echo through the gateway"))
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "echo through the gateway" {
			t.Fatalf("echo = %q, %v", buf, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tool+"/sse", http.NoBody)
		sse, err := newVisitor(t).c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sse.Body.Close() }()
		first := make([]byte, len("data: first\n\n"))
		if _, readErr := io.ReadFull(sse.Body, first); readErr != nil || string(first) != "data: first\n\n" {
			t.Fatalf("first event = %q, %v (it must arrive before the stream ends)", first, readErr)
		}
		newVisitor(t).get(tool + "/sse/release")
		rest, err := io.ReadAll(sse.Body)
		if err != nil || !strings.Contains(string(rest), "data: second") {
			t.Fatalf("rest = %q, %v", rest, err)
		}
	})

	t.Run("back to workspace mode", func(t *testing.T) {
		expectStatus(t, r.as(alice, http.MethodPut, access, map[string]string{"mode": "workspace"}), 200, "workspace")
		anon := newVisitor(t)
		eventually(t, 5*time.Second, "sign-in to be required again", func() bool {
			return anon.noFollow(tool+"/", nil).status == http.StatusFound
		})
		// Upgrades need a session too, and work with one.
		anonConn, _, status := dialUpgrade(t, toolHost, "/ws", nil)
		_ = anonConn.Close()
		if status != http.StatusFound {
			t.Fatalf("anonymous upgrade: %d, want a sign-in redirect", status)
		}
		conn, _, status := dialUpgrade(t, toolHost, "/ws", http.Header{"Cookie": {"nook_visitor=" + aliceV.cookie(tool, "nook_visitor")}})
		_ = conn.Close()
		if status != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade with a session: %d", status)
		}
	})

	t.Run("a stopped app shows why; starting it brings it back", func(t *testing.T) {
		expectStatus(t, r.as(alice, http.MethodPost, appURL("acme", "tool")+"/stop", nil), 200, "stop")
		var res response
		eventually(t, 30*time.Second, "the stopped page", func() bool {
			res = aliceV.get(tool + "/")
			return res.status == http.StatusServiceUnavailable
		})
		if !strings.Contains(res.body, "stopped") || !strings.Contains(res.body, res.header.Get("X-Request-ID")) {
			t.Fatalf("503 page: %s", res.body)
		}
		expectStatus(t, r.as(alice, http.MethodPost, appURL("acme", "tool")+"/start", nil), 200, "start")
		eventually(t, time.Minute, "the app to be back", func() bool { return aliceV.get(tool+"/healthz").status == http.StatusOK })
	})

	t.Run("a new deployment on another port is routed live", func(t *testing.T) {
		before := r.app(alice, "acme", "tool")
		n := r.release("acme", "tool")
		r.waitLive(alice, "acme", "tool", n)
		after := r.app(alice, "acme", "tool")
		if *after.Instance.HostPort == *before.Instance.HostPort {
			t.Fatalf("the new instance reuses port %d; the test proves nothing", *after.Instance.HostPort)
		}
		want := "testapp deployment " + itoa(n)
		eventually(t, 10*time.Second, "the gateway to serve the new deployment", func() bool {
			return strings.TrimSpace(aliceV.get(tool+"/").body) == want
		})
	})

	t.Run("changes are audited", func(t *testing.T) {
		actions := r.auditActions()
		for _, want := range []string{"access.grant", "access.revoke", "access.set_mode", "visitor.sign_in"} {
			if !slices.Contains(actions, want) {
				t.Errorf("no %s in the audit log", want)
			}
		}
	})
}
