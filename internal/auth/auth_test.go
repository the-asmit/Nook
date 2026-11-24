package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

var (
	httpsSite = NewSite(&url.URL{Scheme: "https", Host: "nook.example.com"})
	devSite   = NewSite(&url.URL{Scheme: "http", Host: "localhost:8080"})
)

func TestCookieNamesAndAttributes(t *testing.T) {
	if httpsSite.CookieName("s") != "__Host-s" || devSite.CookieName("s") != "s" {
		t.Fatal("cookie name prefix wrong")
	}
	rec := httptest.NewRecorder()
	httpsSite.SetCookie(rec, SessionCookie, "value", time.Now().Add(time.Hour))
	c := rec.Result().Cookies()[0]
	if c.Name != "__Host-nook_session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie attributes wrong: %+v", c)
	}

	rec = httptest.NewRecorder()
	devSite.ClearCookie(rec, SessionCookie)
	c = rec.Result().Cookies()[0]
	if c.Name != "nook_session" || c.Secure || c.MaxAge >= 0 {
		t.Fatalf("dev clear cookie wrong: %+v", c)
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		origin, referer string
		want            bool
	}{
		{"https://nook.example.com", "", true},
		{"https://evil.example", "https://nook.example.com/", false},
		{"null", "", false},
		{"", "https://nook.example.com/device", true},
		{"", "https://nook.example.com", true},
		{"", "https://nook.example.com.evil.example/", false},
		{"", "", false},
	}
	for _, tc := range cases {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", http.NoBody)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.referer != "" {
			r.Header.Set("Referer", tc.referer)
		}
		if got := httpsSite.SameOrigin(r); got != tc.want {
			t.Errorf("Origin=%q Referer=%q: got %v, want %v", tc.origin, tc.referer, got, tc.want)
		}
	}
}

func TestSafeReturnPath(t *testing.T) {
	cases := map[string]string{
		"/device?user_code=ABCD":        "/device?user_code=ABCD",
		"/":                             "/",
		"":                              "/",
		"//evil.example":                "/",
		`/\evil.example`:                "/",
		"https://evil.example/":         "/",
		"javascript:alert(1)":           "/",
		"device":                        "/",
		"/" + strings.Repeat("a", 3000): "/",
	}
	for in, want := range cases {
		if got := SafeReturnPath(in); got != want {
			t.Errorf("SafeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCSRFToken(t *testing.T) {
	a, b := NewSecret(), NewSecret()
	first, second := CSRFToken(a), CSRFToken(a)
	if first != second || first == CSRFToken(b) {
		t.Fatal("CSRF token must be deterministic per session and differ between sessions")
	}
	if strings.Contains(CSRFToken(a), a) {
		t.Fatal("CSRF token must not reveal the session token")
	}
	p := &Principal{Method: MethodSession, CSRFToken: CSRFToken(a)}
	if !ValidCSRFToken(p, CSRFToken(a)) || ValidCSRFToken(p, CSRFToken(b)) || ValidCSRFToken(p, "") {
		t.Fatal("ValidCSRFToken mismatch")
	}
	if ValidCSRFToken(&Principal{Method: MethodToken}, "") || ValidCSRFToken(nil, "x") {
		t.Fatal("token principals and nil have no CSRF token")
	}
}

func newTestAuthenticator() *Authenticator {
	// Stores are nil: every request below is rejected before any lookup.
	return NewAuthenticator(&Sessions{}, &APITokens{}, httpsSite, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestAuthenticateRejectsMalformedCredentialsWithoutLookup(t *testing.T) {
	a := newTestAuthenticator()
	cases := map[string]func(*http.Request){
		"basic auth":      func(r *http.Request) { r.Header.Set("Authorization", "Basic dXNlcjpwYXNz") },
		"bearer garbage":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-token") },
		"bearer no value": func(r *http.Request) { r.Header.Set("Authorization", "Bearer") },
		"malformed cookie": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-nook_session", Value: "attacker-chosen"})
		},
	}
	for name, mutate := range cases {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		mutate(r)
		if _, err := a.Authenticate(r); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: err = %v, want ErrInvalidCredentials", name, err)
		}
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	if p, err := a.Authenticate(r); p != nil || err != nil {
		t.Errorf("no credentials: got %v, %v; want nil, nil", p, err)
	}
}

func TestRequireAPIRejectsUnauthenticated(t *testing.T) {
	e := gin.New()
	e.GET("/x", newTestAuthenticator().RequireAPI(), func(c *gin.Context) { c.Status(http.StatusOK) })
	for _, auth := range []string{"", "Bearer nook_pat_wrong"} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", http.NoBody)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" ||
			!strings.Contains(rec.Body.String(), `"code":"unauthenticated"`) {
			t.Errorf("auth %q: status %d body %s", auth, rec.Code, rec.Body.String())
		}
	}
}

func TestCheckCSRF(t *testing.T) {
	a := newTestAuthenticator()
	raw := NewSecret()
	session := &Principal{Method: MethodSession, CSRFToken: CSRFToken(raw)}
	req := func(method, origin string) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), method, "/", http.NoBody)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	if err := a.CheckCSRF(req(http.MethodGet, ""), session, ""); err != nil {
		t.Errorf("safe methods are exempt: %v", err)
	}
	if err := a.CheckCSRF(req(http.MethodPost, "https://nook.example.com"), &Principal{Method: MethodToken}, ""); err != nil {
		t.Errorf("bearer tokens are exempt: %v", err)
	}
	if err := a.CheckCSRF(req(http.MethodPost, "https://evil.example"), session, CSRFToken(raw)); err == nil {
		t.Error("cross-origin request accepted")
	}
	if err := a.CheckCSRF(req(http.MethodDelete, "https://nook.example.com"), session, ""); err == nil {
		t.Error("missing token accepted")
	}
	if err := a.CheckCSRF(req(http.MethodPatch, "https://nook.example.com"), session, CSRFToken(NewSecret())); err == nil {
		t.Error("token of another session accepted")
	}
	if err := a.CheckCSRF(req(http.MethodPost, "https://nook.example.com"), session, CSRFToken(raw)); err != nil {
		t.Errorf("valid request rejected: %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	ok := Config{SessionIdleTimeout: time.Hour, SessionAbsoluteTimeout: 24 * time.Hour}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := Config{SessionIdleTimeout: 48 * time.Hour, SessionAbsoluteTimeout: 24 * time.Hour}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "must not exceed") {
		t.Fatalf("idle > absolute accepted: %v", err)
	}
	if err := (&Config{SessionIdleTimeout: time.Second, SessionAbsoluteTimeout: time.Hour}).Validate(); err == nil {
		t.Fatal("tiny idle timeout accepted")
	}
}

func TestNormalizeTokenName(t *testing.T) {
	if n, err := NormalizeTokenName("  ci  "); err != nil || n != "ci" {
		t.Fatalf("got %q, %v", n, err)
	}
	for _, bad := range []string{"", "   ", strings.Repeat("x", 101), "a\nb"} {
		if _, err := NormalizeTokenName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
