//go:build integration

package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/the-asmit/nook/internal/cli"
)

// TestAccessEndpointsAreTenantScoped: non-members get 404 for every
// access endpoint (as for a missing app), members may view but not
// change, and admins change.
func TestAccessEndpointsAreTenantScoped(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	outsider := e.newUser("carol@nook.test")
	member := e.newUser("dave@nook.test")
	expectStatus(t, e.as(alice, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Team", "slug": "team"}), 201, "create workspace")
	expectStatus(t, e.as(alice, http.MethodPost, "/api/v1/workspaces/team/invitations", map[string]string{"email": member.email, "role": "member"}), 201, "invite")
	e.newUserSignIn(member.email)
	expectStatus(t, e.as(alice, http.MethodPost, appsURL("team"), map[string]any{"slug": "web"}), 201, "create app")
	access := appURL("team", "web") + "/access"
	expectStatus(t, e.as(alice, http.MethodPost, access+"/grants", map[string]any{"emails": []string{"friend@partner.test"}}), 200, "grant")

	calls := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, access, nil},
		{http.MethodPut, access, map[string]string{"mode": "restricted"}},
		{http.MethodPost, access + "/grants", map[string]any{"emails": []string{"x@partner.test"}}},
		{http.MethodDelete, access + "/grants/friend@partner.test", nil},
	}
	for _, c := range calls {
		got := e.as(outsider, c.method, c.path, c.body)
		missing := e.as(outsider, c.method, strings.Replace(c.path, "/apps/web/", "/apps/nope/", 1), c.body)
		if got.status != http.StatusNotFound || got.errorCode(t) != missing.errorCode(t) {
			t.Errorf("outsider %s %s: %d %s", c.method, c.path, got.status, got.body)
		}
	}
	expectStatus(t, e.as(member, http.MethodGet, access, nil), 200, "member views")
	for _, c := range calls[1:] {
		expectStatus(t, e.as(member, c.method, c.path, c.body), http.StatusForbidden, "member "+c.method+" "+c.path)
	}
	var view struct {
		Mode   string `json:"mode"`
		Grants []struct {
			Email string `json:"email"`
		} `json:"grants"`
	}
	e.as(alice, http.MethodGet, access, nil).json(t, &view)
	if view.Mode != "workspace" || len(view.Grants) != 1 || view.Grants[0].Email != "friend@partner.test" {
		t.Fatalf("nothing may have changed: %+v", view)
	}

	// Input is validated.
	for name, body := range map[string]any{
		"unknown mode":   map[string]string{"mode": "everyone"},
		"no emails":      map[string]any{"emails": []string{}},
		"display name":   map[string]any{"emails": []string{"Friend <f@partner.test>"}},
		"too many":       map[string]any{"emails": manyEmails(51)},
		"not an address": map[string]any{"emails": []string{"nope"}},
	} {
		path := access
		method := http.MethodPut
		if _, ok := body.(map[string]any); ok {
			path, method = access+"/grants", http.MethodPost
		}
		expectStatus(t, e.as(alice, method, path, body), http.StatusBadRequest, name)
	}
	expectStatus(t, e.as(alice, http.MethodDelete, access+"/grants/stranger@partner.test", nil), http.StatusNotFound, "revoke without a grant")
}

// TestPublicAppsNeedTheInstanceSetting: with NOOK_ALLOW_PUBLIC_APPS=false
// no app can be made public, and an app made public earlier is served as
// a workspace app.
func TestPublicAppsNeedTheInstanceSetting(t *testing.T) {
	e := startEnvWith(t, map[string]string{"NOOK_ALLOW_PUBLIC_APPS": "false"})
	alice := e.adminAlice()
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": "web"}), 201, "create app")
	access := appURL(alice.personal, "web") + "/access"
	res := e.as(alice, http.MethodPut, access, map[string]string{"mode": "public"})
	if res.status != http.StatusForbidden {
		t.Fatalf("public mode on an instance that forbids it: %d %s", res.status, res.body)
	}
	e.exec("UPDATE apps SET access_mode = 'public'")
	var view struct {
		Mode          string `json:"mode"`
		Effective     string `json:"effective"`
		PublicAllowed bool   `json:"public_allowed"`
	}
	e.as(alice, http.MethodGet, access, nil).json(t, &view)
	if view.Mode != "public" || view.Effective != "workspace" || view.PublicAllowed {
		t.Fatalf("access = %+v", view)
	}
	routes := e.internal(testGatewaySecret, "/internal/v1/routes")
	if routes.status != http.StatusOK || !strings.Contains(routes.body, `"access":"workspace"`) {
		t.Fatalf("route served as: %d %s", routes.status, routes.body)
	}
	// Visitors are sent to sign in.
	e.startGateway(nil)
	if got := newVisitor(t).noFollow(appOrigin(alice.personal, "web")+"/", nil); got.status != http.StatusFound {
		t.Fatalf("anonymous visitor: %d, want a sign-in redirect", got.status)
	}
}

// TestInternalAPIOnlyAnswersGateways: without the gateways' secret the
// internal API and the auth host pages look like they do not exist.
func TestInternalAPIOnlyAnswersGateways(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	for _, secret := range []string{"", "wrong", testGatewaySecret + "x", alice.token} {
		for _, path := range []string{"/internal/v1/routes", "/internal/v1/tls/hosts/auth.apps.localhost", "/internal/v1/certificates/acme_account+key"} {
			if res := e.internal(secret, path); res.status != http.StatusNotFound {
				t.Errorf("GET %s with %q: %d", path, secret, res.status)
			}
		}
		req := newRequest(t, http.MethodGet, e.base+"/_visitor/start?app=x", http.NoBody)
		if secret != "" {
			req.Header.Set("X-Nook-Gateway-Secret", secret)
		}
		if res := send(t, http.DefaultClient, req); res.status != http.StatusNotFound {
			t.Errorf("auth host page with %q: %d", secret, res.status)
		}
	}
	if res := e.internal(testGatewaySecret, "/internal/v1/tls/hosts/auth.apps.localhost"); res.status != http.StatusNoContent {
		t.Fatalf("auth host check: %d", res.status)
	}
	if res := e.internal(testGatewaySecret, "/internal/v1/tls/hosts/random.example.com"); res.status != http.StatusNotFound {
		t.Fatalf("unknown host check: %d", res.status)
	}
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": "web"}), 201, "create app")
	if res := e.internal(testGatewaySecret, "/internal/v1/tls/hosts/web--"+alice.personal+".apps.localhost"); res.status != http.StatusNoContent {
		t.Fatalf("app host check: %d", res.status)
	}
}

// TestCertificatesAreStoredSealed: what a gateway stores comes back
// unchanged but is encrypted at rest.
func TestCertificatesAreStoredSealed(t *testing.T) {
	e := startEnv(t)
	put := newRequest(t, http.MethodPut, e.base+"/internal/v1/certificates/app--ws.apps.example.com", jsonBody(t, map[string][]byte{"data": []byte("-----BEGIN PRIVATE KEY-----secret")}))
	put.Header.Set("Authorization", "Bearer "+testGatewaySecret)
	put.Header.Set("Content-Type", "application/json")
	if res := send(t, http.DefaultClient, put); res.status != http.StatusNoContent {
		t.Fatalf("put: %d %s", res.status, res.body)
	}
	if n := e.count("SELECT count(*) FROM gateway_certificates WHERE position('PRIVATE KEY'::bytea in data) > 0"); n != 0 {
		t.Fatal("the certificate is stored in plain form")
	}
	res := e.internal(testGatewaySecret, "/internal/v1/certificates/app--ws.apps.example.com")
	if res.status != http.StatusOK || !strings.Contains(res.body, `"data":"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tc2VjcmV0"`) {
		t.Fatalf("get: %d %s", res.status, res.body)
	}
	if res := e.internal(testGatewaySecret, "/internal/v1/certificates/..%2Fetc"); res.status != http.StatusNotFound {
		t.Fatalf("invalid name: %d", res.status)
	}
}

// TestDoubleHyphenSlugsAreRejected: "--" separates app and workspace in
// host names, so neither slug may contain it.
func TestDoubleHyphenSlugsAreRejected(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	expectStatus(t, e.as(alice, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Bad", "slug": "bad--ws"}), 400, "workspace slug with --")
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": "bad--app"}), 400, "app slug with --")
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": "good-app"}), 201, "single hyphens")
	// The host label <app>--<workspace> must fit DNS's 63 characters.
	long := strings.Repeat("w", 40)
	expectStatus(t, e.as(alice, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Long", "slug": long}), 201, "long workspace slug")
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(long), map[string]any{"slug": strings.Repeat("a", 22)}), 400, "label over 63 characters")
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(long), map[string]any{"slug": strings.Repeat("a", 21)}), 201, "label of 63 characters")
}

func manyEmails(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "user" + strconv.Itoa(i) + "@partner.test"
	}
	return out
}

// internal calls the internal API with a gateway secret.
func (e *env) internal(secret, path string) response {
	e.t.Helper()
	req := newRequest(e.t, http.MethodGet, e.base+path, http.NoBody)
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return send(e.t, http.DefaultClient, req)
}

// TestAccessCLI drives nook access, apps info and open against the server.
func TestAccessCLI(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": "web"}), 201, "create app")
	c := &cliRunner{t: t, env: map[string]string{
		"XDG_CONFIG_HOME": t.TempDir(), "NOOK_SERVER": e.base, "NOOK_TOKEN": alice.token, "NOOK_WORKSPACE": alice.personal,
	}}
	url := appOrigin(alice.personal, "web") + "/"
	steps := []struct {
		args []string
		want []string
	}{
		{[]string{"access", "show", "web"}, []string{"Access:  workspace", "workspace members", "Grants:  none"}},
		{[]string{"access", "grant", "web", "friend@partner.test", "Other@Partner.test"}, []string{"friend@partner.test", "other@partner.test"}},
		{[]string{"access", "set", "web", "--mode", "restricted"}, []string{"Access:  restricted", "admins and owners"}},
		{[]string{"access", "revoke", "web", "friend@partner.test"}, []string{"other@partner.test"}},
		{[]string{"access", "set", "web", "--mode", "public"}, []string{"Access:  public", "anyone, without signing in"}},
		{[]string{"apps", "info", "web"}, []string{url, "public"}},
	}
	for _, s := range steps {
		code, out, errOut := c.run(s.args...)
		if code != 0 {
			t.Fatalf("nook %s: exit %d\n%s%s", strings.Join(s.args, " "), code, out, errOut)
		}
		for _, w := range s.want {
			if !strings.Contains(out, w) {
				t.Errorf("nook %s: output lacks %q:\n%s", strings.Join(s.args, " "), w, out)
			}
		}
	}
	if code, out, _ := c.run("access", "show", "web"); code != 0 || strings.Contains(out, "friend@partner.test") {
		t.Fatalf("revoked grant still listed: %s", out)
	}
	if code, _, errOut := c.run("access", "set", "web", "--mode", "everyone"); code != 2 || !strings.Contains(errOut, "--mode must be") {
		t.Fatalf("bad mode: %d %s", code, errOut)
	}

	var opened string
	var stdout, stderr lockedBuffer
	code := cli.Execute(context.Background(), &cli.App{
		Stdout: &stdout, Stderr: &stderr, Getenv: func(k string) string { return c.env[k] },
		OpenBrowser: func(u string) error { opened = u; return nil },
	}, []string{"open", "web"})
	if code != 0 || opened != url || strings.TrimSpace(stdout.String()) != url {
		t.Fatalf("open: exit %d, opened %q, printed %q %s", code, opened, stdout.String(), stderr.String())
	}
}
