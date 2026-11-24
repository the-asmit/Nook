//go:build integration

package server

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/the-asmit/nook/internal/testinfra"
)

type deviceStartResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (e *env) startDevice(t *testing.T) deviceStartResp {
	t.Helper()
	r := e.bearer("", http.MethodPost, "/api/v1/auth/device", map[string]string{"client_name": "nook CLI on test-laptop"})
	var d deviceStartResp
	r.json(t, &d)
	if r.status != http.StatusOK || d.DeviceCode == "" {
		t.Fatalf("start device flow: %d %s", r.status, r.body)
	}
	return d
}

func (e *env) poll(deviceCode string) response {
	return e.bearer("", http.MethodPost, "/api/v1/auth/device/token", map[string]string{"device_code": deviceCode})
}

// allowNextPoll moves the last poll into the past, standing in for the
// client waiting out its interval without the test sleeping.
func (e *env) allowNextPoll() {
	e.exec("UPDATE device_authorizations SET last_polled_at = now() - interval '1 hour'")
}

var userCodeInPage = regexp.MustCompile(`value="([A-Z]{4}-[A-Z]{4})"`)

func TestDeviceFlowIssuesTokenExactlyOnce(t *testing.T) {
	e := startEnv(t)
	d := e.startDevice(t)
	if d.VerificationURI != e.base+"/device" || d.VerificationURIComplete != d.VerificationURI+"?user_code="+d.UserCode ||
		d.ExpiresIn != 600 || d.Interval != 1 {
		t.Fatalf("start response = %+v", d)
	}
	if n := e.count("SELECT count(*) FROM device_authorizations WHERE octet_length(device_code_hash) = 32"); n != 1 {
		t.Fatal("device code must be stored hashed")
	}

	if r := e.poll(d.DeviceCode); r.status != http.StatusBadRequest || r.errorCode(t) != "authorization_pending" {
		t.Fatalf("first poll: %d %s", r.status, r.body)
	}
	if r := e.poll(d.DeviceCode); r.errorCode(t) != "slow_down" {
		t.Fatalf("immediate re-poll: %d %s", r.status, r.body)
	}
	if n := e.count("SELECT poll_interval_seconds FROM device_authorizations"); n != 6 {
		t.Fatalf("interval after slow_down = %d, want 1+5", n)
	}

	// The person signs in and approves in the browser.
	b := e.browser()
	b.signIn(testinfra.DexAlice)
	page := send(t, b.c, newRequest(t, http.MethodGet, d.VerificationURIComplete, http.NoBody))
	if m := userCodeInPage.FindStringSubmatch(page.body); len(m) != 2 || m[1] != d.UserCode {
		t.Fatalf("code not pre-filled on the approval page")
	}
	confirm := b.postForm("/device", url.Values{"user_code": {strings.ToLower(d.UserCode)}}, true)
	if confirm.status != http.StatusOK || !strings.Contains(confirm.body, "nook CLI on test-laptop") {
		t.Fatalf("confirm page: %d %.300s", confirm.status, confirm.body)
	}
	if r := b.postForm("/device/decision", url.Values{"user_code": {d.UserCode}, "decision": {"approve"}}, true); !strings.Contains(r.body, "Device approved") {
		t.Fatalf("approve: %d %.300s", r.status, r.body)
	}

	e.allowNextPoll()
	r := e.poll(d.DeviceCode)
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	r.json(t, &tok)
	if r.status != http.StatusOK || !strings.HasPrefix(tok.AccessToken, "nook_pat_") || tok.TokenType != "Bearer" {
		t.Fatalf("token poll: %d %s", r.status, r.body)
	}
	if me := e.bearer(tok.AccessToken, http.MethodGet, "/api/v1/me", nil); me.status != http.StatusOK || !strings.Contains(me.body, `"auth_method":"token"`) {
		t.Fatalf("issued token does not work: %d %s", me.status, me.body)
	}

	e.allowNextPoll()
	if r := e.poll(d.DeviceCode); r.errorCode(t) != "invalid_grant" {
		t.Fatalf("second redemption: %d %s", r.status, r.body)
	}
	if n := e.count("SELECT count(*) FROM api_tokens"); n != 1 {
		t.Fatalf("api tokens = %d, want exactly 1", n)
	}
	actions := e.auditActions()
	for _, want := range []string{"device.approve", "token.create"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit log lacks %s: %v", want, actions)
		}
	}
}

func TestDeviceFlowDenied(t *testing.T) {
	e := startEnv(t)
	d := e.startDevice(t)
	b := e.browser()
	b.signIn(testinfra.DexAlice)
	if r := b.postForm("/device/decision", url.Values{"user_code": {d.UserCode}, "decision": {"deny"}}, true); !strings.Contains(r.body, "Device denied") {
		t.Fatalf("deny: %d", r.status)
	}
	if r := e.poll(d.DeviceCode); r.errorCode(t) != "access_denied" {
		t.Fatalf("poll after deny: %s", r.body)
	}
	// A decided code cannot be decided again.
	if r := b.postForm("/device/decision", url.Values{"user_code": {d.UserCode}, "decision": {"approve"}}, true); r.status != http.StatusBadRequest {
		t.Fatalf("re-deciding: %d", r.status)
	}
	if !slices.Contains(e.auditActions(), "device.deny") {
		t.Fatal("denial not audited")
	}
}

func TestDeviceCodeExpires(t *testing.T) {
	e := startEnv(t)
	d := e.startDevice(t)
	e.exec("UPDATE device_authorizations SET expires_at = now() - interval '1 second'")
	if r := e.poll(d.DeviceCode); r.errorCode(t) != "expired_token" {
		t.Fatalf("expired poll: %s", r.body)
	}
	if n := e.count("SELECT count(*) FROM device_authorizations WHERE status = 'expired'"); n != 1 {
		t.Fatal("status not set to expired")
	}
	b := e.browser()
	b.signIn(testinfra.DexAlice)
	if r := b.postForm("/device", url.Values{"user_code": {d.UserCode}}, true); r.status != http.StatusBadRequest {
		t.Fatalf("expired code accepted in the browser: %d", r.status)
	}
}

func TestDeviceEndpointsAreRateLimited(t *testing.T) {
	e := startEnv(t)
	for i := range 10 {
		if r := e.bearer("", http.MethodPost, "/api/v1/auth/device", map[string]string{}); r.status != http.StatusOK {
			t.Fatalf("start %d: %d", i, r.status)
		}
	}
	r := e.bearer("", http.MethodPost, "/api/v1/auth/device", map[string]string{})
	if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") == "" || r.errorCode(t) != "rate_limited" {
		t.Fatalf("11th start: %d %s", r.status, r.body)
	}

	// Guessing device codes: every attempt counts, valid or not.
	for i := range 60 {
		if r := e.poll("guess-" + strings.Repeat("a", i%5)); r.status == http.StatusTooManyRequests {
			t.Fatalf("limited after only %d polls", i)
		}
	}
	if r := e.poll("one-more"); r.status != http.StatusTooManyRequests {
		t.Fatalf("61st poll: %d", r.status)
	}
}

func TestUserCodeGuessingIsLimited(t *testing.T) {
	e := startEnv(t)
	b := e.browser()
	b.signIn(testinfra.DexAlice)
	for i := range 10 {
		if r := b.postForm("/device", url.Values{"user_code": {"BCDF-GHJK"}}, true); r.status != http.StatusBadRequest {
			t.Fatalf("guess %d: %d", i, r.status)
		}
	}
	if r := b.postForm("/device", url.Values{"user_code": {"BCDF-GHJK"}}, true); r.status != http.StatusTooManyRequests {
		t.Fatalf("11th guess: %d", r.status)
	}
}

func TestDeviceApprovalNeedsSignInAndCSRF(t *testing.T) {
	e := startEnv(t)
	d := e.startDevice(t)
	anon := e.browser()
	anon.c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r := send(t, anon.c, newRequest(t, http.MethodGet, d.VerificationURIComplete, http.NoBody))
	if r.status != http.StatusSeeOther || !strings.HasPrefix(r.header.Get("Location"), "/signin?return_to=") {
		t.Fatalf("anonymous approval page: %d %q", r.status, r.header.Get("Location"))
	}

	b := e.browser()
	b.signIn(testinfra.DexAlice)
	if r := b.postForm("/device/decision", url.Values{"user_code": {d.UserCode}, "decision": {"approve"}}, false); r.status != http.StatusForbidden {
		t.Fatalf("approval without CSRF token: %d", r.status)
	}
	if r := e.poll(d.DeviceCode); r.errorCode(t) != "authorization_pending" {
		t.Fatalf("request was approved anyway: %s", r.body)
	}
}
