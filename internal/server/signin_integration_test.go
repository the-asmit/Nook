//go:build integration

package server

import (
	"context"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/testinfra"
)

func TestBrowserSignInProvisionsAccount(t *testing.T) {
	e := startEnv(t)
	b := e.browser()
	r := b.signIn(testinfra.DexAlice)
	if r.status != http.StatusOK || !strings.Contains(r.body, "Signed in") || r.url.Path != "/" {
		t.Fatalf("sign-in ended at %s with %d: %.300s", r.url, r.status, r.body)
	}
	if !strings.Contains(r.header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("HTML page without CSP")
	}

	var me struct {
		User struct {
			Email           string `json:"email"`
			IsInstanceAdmin bool   `json:"is_instance_admin"`
		} `json:"user"`
		AuthMethod string `json:"auth_method"`
	}
	b.api(http.MethodGet, "/api/v1/me", nil, nil).json(t, &me)
	if me.User.Email != testinfra.DexAlice || !me.User.IsInstanceAdmin || me.AuthMethod != "session" {
		t.Fatalf("me = %+v", me)
	}
	if n := e.count(`SELECT count(*) FROM workspaces w JOIN memberships m ON m.workspace_id = w.id
		WHERE w.personal_owner_id IS NOT NULL AND m.role = 'owner'`); n != 1 {
		t.Fatalf("personal workspaces = %d, want 1", n)
	}
	// The issuer+subject pair is the identity, not the email.
	if n := e.count("SELECT count(*) FROM users WHERE oidc_issuer = $1 AND oidc_subject <> ''", shared.dex.IssuerURL); n != 1 {
		t.Fatal("user not linked to the issuer")
	}
	if n := e.count("SELECT count(*) FROM sessions WHERE octet_length(token_hash) = 32 AND revoked_at IS NULL"); n != 1 {
		t.Fatal("expected exactly one active, hashed session")
	}
	if got := e.auditActions(); !slices.Equal(got, []string{"user.create", "user.instance_admin_grant", "workspace.create", "auth.sign_in"}) {
		t.Fatalf("audit = %v", got)
	}
}

func TestUninvitedUserIsRefusedAndNothingIsCreated(t *testing.T) {
	e := startEnv(t)
	r := e.browser().signIn(testinfra.DexMallory)
	if r.status != http.StatusForbidden || !strings.Contains(r.body, "You have not been invited") {
		t.Fatalf("status %d: %.300s", r.status, r.body)
	}
	for _, table := range []string{"users", "workspaces", "memberships", "sessions", "audit_log"} {
		if n := e.count("SELECT count(*) FROM " + table); n != 0 {
			t.Errorf("%s has %d rows after a refused sign-in", table, n)
		}
	}
	if strings.Contains(e.logs.String(), testinfra.DexMallory) {
		t.Error("the refused person's email address was logged")
	}
}

func TestInvitationAdmitsOtherDomain(t *testing.T) {
	e := startEnv(t)
	alice := e.browser()
	alice.signIn(testinfra.DexAlice)
	if r := alice.postAPI("/api/v1/workspaces", map[string]string{"name": "Team", "slug": "team"}); r.status != http.StatusCreated {
		t.Fatalf("create workspace: %d %s", r.status, r.body)
	}
	if r := alice.postAPI("/api/v1/workspaces/team/invitations", map[string]string{"email": testinfra.DexBob, "role": "admin"}); r.status != http.StatusCreated {
		t.Fatalf("invite: %d %s", r.status, r.body)
	}

	bob := e.browser()
	if r := bob.signIn(testinfra.DexBob); r.status != http.StatusOK {
		t.Fatalf("invited user refused: %d %.300s", r.status, r.body)
	}
	var ws struct {
		Role string `json:"role"`
	}
	r := bob.api(http.MethodGet, "/api/v1/workspaces/team", nil, nil)
	r.json(t, &ws)
	if r.status != http.StatusOK || ws.Role != "admin" {
		t.Fatalf("bob in team: %d %s", r.status, r.body)
	}
	if n := e.count("SELECT count(*) FROM invitations WHERE accepted_at IS NOT NULL"); n != 1 {
		t.Fatal("invitation not marked accepted")
	}
	// Admitted by invitation, bob may sign in again although his domain is
	// not allowed and no invitation is open any more.
	if r := e.browser().signIn(testinfra.DexBob); r.status != http.StatusOK {
		t.Fatalf("second sign-in refused: %d", r.status)
	}
	if !slices.Contains(e.auditActions(), "invitation.accept") {
		t.Fatal("invitation acceptance not audited")
	}
}

func TestSessionFixationIsPrevented(t *testing.T) {
	e := startEnv(t)
	b := e.browser()
	planted := auth.NewSecret() // well-formed value an attacker could plant
	b.setSessionCookie(planted)
	b.signIn(testinfra.DexAlice)

	issued := b.sessionCookie()
	if issued == "" || issued == planted {
		t.Fatalf("server adopted the planted session ID")
	}
	attacker := e.browser()
	attacker.setSessionCookie(planted)
	if r := attacker.api(http.MethodGet, "/api/v1/me", nil, nil); r.status != http.StatusUnauthorized {
		t.Fatalf("planted session works: %d", r.status)
	}
}

func TestSessionRotatesOnEverySignIn(t *testing.T) {
	e := startEnv(t)
	b := e.browser()
	b.signIn(testinfra.DexAlice)
	first := b.sessionCookie()
	b.signIn(testinfra.DexAlice)
	second := b.sessionCookie()
	if second == "" || second == first {
		t.Fatal("signing in again did not issue a new session")
	}
	old := e.browser()
	old.setSessionCookie(first)
	if r := old.api(http.MethodGet, "/api/v1/me", nil, nil); r.status != http.StatusUnauthorized {
		t.Fatalf("previous session still valid: %d", r.status)
	}
}

func TestExpiredRevokedAndDisabledSessionsAreRejected(t *testing.T) {
	e := startEnv(t)
	cases := map[string]func(b *browser){
		"idle timeout": func(*browser) {
			e.exec("UPDATE sessions SET idle_expires_at = now() - interval '1 second'")
		},
		"absolute timeout": func(*browser) {
			e.exec("UPDATE sessions SET idle_expires_at = now() - interval '2 seconds', absolute_expires_at = now() - interval '1 second'")
		},
		"logout": func(b *browser) {
			if r := b.postAPI("/api/v1/auth/logout", nil); r.status != http.StatusNoContent {
				t.Fatalf("logout: %d %s", r.status, r.body)
			}
		},
		"disabled user": func(*browser) {
			e.exec("UPDATE users SET disabled_at = now()")
		},
	}
	for name, invalidate := range cases {
		t.Run(name, func(t *testing.T) {
			// The cases run in random (map) order; each starts clean.
			e.exec("DELETE FROM sessions")
			e.exec("UPDATE users SET disabled_at = NULL")
			b := e.browser()
			b.signIn(testinfra.DexAlice)
			cookie := b.sessionCookie()
			if r := b.api(http.MethodGet, "/api/v1/me", nil, nil); r.status != http.StatusOK {
				t.Fatalf("fresh session rejected: %d", r.status)
			}
			invalidate(b)
			replay := e.browser()
			replay.setSessionCookie(cookie)
			if r := replay.api(http.MethodGet, "/api/v1/me", nil, nil); r.status != http.StatusUnauthorized {
				t.Fatalf("session still accepted: %d", r.status)
			}
		})
	}
	// The cases run in random (map) order: disable explicitly.
	e.exec("UPDATE users SET disabled_at = now()")
	if r := e.browser().signIn(testinfra.DexAlice); r.status != http.StatusForbidden || !strings.Contains(r.body, "disabled") {
		t.Fatalf("disabled user signed in: %d", r.status)
	}
}

func TestCSRFProtection(t *testing.T) {
	e := startEnv(t)
	b := e.browser()
	b.signIn(testinfra.DexAlice)
	token := b.csrf()
	body := map[string]string{"name": "X", "slug": "x"}

	cases := map[string]map[string]string{
		"no token":           {"Origin": e.base},
		"wrong token":        {"Origin": e.base, "X-CSRF-Token": auth.CSRFToken(auth.NewSecret())},
		"cross-site origin":  {"Origin": "https://evil.example", "X-CSRF-Token": token},
		"no origin/referer":  {"X-CSRF-Token": token},
		"cross-site referer": {"Referer": "https://evil.example/page", "X-CSRF-Token": token},
	}
	for name, headers := range cases {
		r := b.api(http.MethodPost, "/api/v1/workspaces", body, headers)
		if r.status != http.StatusForbidden || r.errorCode(t) != "csrf_failed" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if n := e.count("SELECT count(*) FROM workspaces WHERE slug = 'x'"); n != 0 {
		t.Fatal("a rejected request changed state")
	}
	if r := b.api(http.MethodPost, "/api/v1/workspaces", body, map[string]string{"Referer": e.base + "/", "X-CSRF-Token": token}); r.status != http.StatusCreated {
		t.Fatalf("same-origin request with token: %d %s", r.status, r.body)
	}

	// HTML forms are protected the same way.
	if r := b.postForm("/auth/logout", url.Values{}, false); r.status != http.StatusForbidden {
		t.Fatalf("logout form without token: %d", r.status)
	}
	if r := b.api(http.MethodGet, "/api/v1/me", nil, nil); r.status != http.StatusOK {
		t.Fatal("rejected logout still signed the user out")
	}
	if r := b.postForm("/auth/logout", url.Values{}, true); r.status != http.StatusOK || !strings.Contains(r.body, "Signed out") {
		t.Fatalf("logout form with token: %d", r.status)
	}
}

// stopAtCallback configures b to stop at the redirect back to Nook and
// returns the callback URL Dex produced.
func stopAtCallback(t *testing.T, b *browser) *url.URL {
	t.Helper()
	action := b.openDexForm()
	b.c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Path == "/auth/callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	defer func() { b.c.CheckRedirect = nil }()
	r := b.submitDex(action, testinfra.DexAlice)
	loc, err := r.url.Parse(r.header.Get("Location"))
	if err != nil || loc.Path != "/auth/callback" {
		t.Fatalf("expected a redirect to the callback, got %d %q", r.status, r.header.Get("Location"))
	}
	return loc
}

func TestCallbackTamperingIsRejected(t *testing.T) {
	e := startEnv(t)

	t.Run("state mismatch", func(t *testing.T) {
		b := e.browser()
		cb := stopAtCallback(t, b)
		q := cb.Query()
		q.Set("state", auth.NewSecret())
		cb.RawQuery = q.Encode()
		r := send(t, b.c, newRequest(t, http.MethodGet, cb.String(), http.NoBody))
		if r.status != http.StatusBadRequest || b.sessionCookie() != "" {
			t.Fatalf("status %d, cookie %q", r.status, b.sessionCookie())
		}
	})
	t.Run("callback in another browser", func(t *testing.T) {
		cb := stopAtCallback(t, e.browser())
		other := e.browser() // has no sign-in flow cookie: login CSRF attempt
		r := send(t, other.c, newRequest(t, http.MethodGet, cb.String(), http.NoBody))
		if r.status != http.StatusBadRequest || other.sessionCookie() != "" {
			t.Fatalf("status %d", r.status)
		}
	})
	t.Run("replayed callback", func(t *testing.T) {
		b := e.browser()
		cb := stopAtCallback(t, b)
		if r := send(t, b.c, newRequest(t, http.MethodGet, cb.String(), http.NoBody)); r.status != http.StatusOK {
			t.Fatalf("first callback: %d", r.status)
		}
		if r := send(t, b.c, newRequest(t, http.MethodGet, cb.String(), http.NoBody)); r.status != http.StatusBadRequest {
			t.Fatalf("replayed callback: %d", r.status)
		}
	})
	t.Run("provider error", func(t *testing.T) {
		b := e.browser()
		b.openDexForm()
		r := send(t, b.c, newRequest(t, http.MethodGet, e.base+"/auth/callback?error=access_denied&state=x", http.NoBody))
		if r.status != http.StatusBadRequest || !strings.Contains(r.body, "canceled") {
			t.Fatalf("status %d", r.status)
		}
	})
	if n := e.count("SELECT count(*) FROM sessions"); n != 1 {
		t.Fatalf("sessions = %d, want only the one legitimate sign-in", n)
	}
}

func TestOpenRedirectIsPrevented(t *testing.T) {
	e := startEnv(t)
	b := e.browser()
	r := send(t, b.c, newRequest(t, http.MethodGet, e.base+"/auth/login?return_to=//evil.example/x", http.NoBody))
	action, err := r.url.Parse(html.UnescapeString(formAction.FindStringSubmatch(r.body)[1]))
	if err != nil {
		t.Fatal(err)
	}
	final := b.submitDex(action, testinfra.DexAlice)
	if final.url.Host != strings.TrimPrefix(e.base, "http://") || final.url.Path != "/" {
		t.Fatalf("redirected to %s", final.url)
	}
}

func TestUnverifiedEmailIsRejected(t *testing.T) {
	e := startEnv(t)
	st := store.NewStore(e.db)
	svc := identity.NewService(st, auth.NewSessions(st, auth.Config{SessionIdleTimeout: time.Hour, SessionAbsoluteTimeout: 2 * time.Hour}),
		identity.NewPolicy(&identity.Config{AllowedEmailDomains: []string{"nook.test"}}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := svc.SignIn(context.Background(), &identity.Identity{
		Issuer: shared.dex.IssuerURL, Subject: "unverified", Email: "carol@nook.test", EmailVerified: false,
	}, identity.RequestMeta{})
	if !errors.Is(err, identity.ErrEmailNotVerified) {
		t.Fatalf("err = %v, want ErrEmailNotVerified", err)
	}
	if n := e.count("SELECT count(*) FROM users"); n != 0 {
		t.Fatal("user created for an unverified email")
	}
}
