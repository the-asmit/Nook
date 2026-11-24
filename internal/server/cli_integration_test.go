//go:build integration

package server

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/cli"
	"github.com/the-asmit/nook/internal/testinfra"
)

// lockedBuffer lets the test read CLI output while the CLI writes it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type cliRunner struct {
	t   *testing.T
	env map[string]string
}

func (c *cliRunner) run(args ...string) (int, string, string) {
	c.t.Helper()
	var stdout, stderr lockedBuffer
	code := cli.Execute(context.Background(), &cli.App{
		Stdout: &stdout, Stderr: &stderr, Getenv: func(k string) string { return c.env[k] },
	}, args)
	return code, stdout.String(), stderr.String()
}

var printedCode = regexp.MustCompile(`code:\s+([A-Z]{4}-[A-Z]{4})`)

// TestCLIEndToEnd drives the real CLI against the real server: device
// login approved in a browser, then workspace and token commands, then
// logout revoking the token.
func TestCLIEndToEnd(t *testing.T) {
	e := startEnv(t)
	configHome := t.TempDir()
	c := &cliRunner{t: t, env: map[string]string{"XDG_CONFIG_HOME": configHome}}

	var stderr lockedBuffer
	var stdout lockedBuffer
	done := make(chan int, 1)
	go func() {
		done <- cli.Execute(context.Background(), &cli.App{
			Stdout: &stdout, Stderr: &stderr, Getenv: func(k string) string { return c.env[k] },
		}, []string{"login", e.base, "--no-browser"})
	}()

	// Wait (polling with a deadline) for the CLI to print its code.
	var userCode string
	deadline := time.Now().Add(30 * time.Second)
	for userCode == "" {
		if m := printedCode.FindStringSubmatch(stderr.String()); m != nil {
			userCode = m[1]
		} else if time.Now().After(deadline) {
			t.Fatalf("CLI printed no code: %s", stderr.String())
		}
	}
	b := e.browser()
	b.signIn(testinfra.DexAlice)
	if r := b.postForm("/device/decision", url.Values{"user_code": {userCode}, "decision": {"approve"}}, true); !strings.Contains(r.body, "Device approved") {
		t.Fatalf("approve: %d", r.status)
	}
	select {
	case code := <-done:
		if code != 0 || !strings.Contains(stdout.String(), "Logged in to "+e.base+" as "+testinfra.DexAlice) {
			t.Fatalf("login exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("login did not finish: %s", stderr.String())
	}

	cfgPath := filepath.Join(configHome, "nook", "config.json")
	info, err := os.Stat(cfgPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", info, err)
	}

	if code, out, _ := c.run("whoami"); code != 0 || !strings.Contains(out, testinfra.DexAlice) {
		t.Fatalf("whoami: %d %s", code, out)
	}
	if code, out, errOut := c.run("workspace", "create", "cli-team", "--name", "CLI Team"); code != 0 || !strings.Contains(out, "cli-team") {
		t.Fatalf("workspace create: %d %s %s", code, out, errOut)
	}
	if code, out, _ := c.run("workspace", "use", "cli-team"); code != 0 || !strings.Contains(out, "cli-team") {
		t.Fatalf("workspace use: %d %s", code, out)
	}
	if code, out, _ := c.run("workspace", "list"); code != 0 || !strings.Contains(out, "*  cli-team") {
		t.Fatalf("workspace list: %d %q", code, out)
	}
	if code, out, _ := c.run("--output", "json", "workspace", "list"); code != 0 || !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Fatalf("json list: %d %s", code, out)
	}
	if code, _, errOut := c.run("workspace", "use", "not-mine"); code != 1 || !strings.Contains(errOut, "request ID") {
		t.Fatalf("unknown workspace: %d %s", code, errOut)
	}

	code, out, _ := c.run("token", "create", "--name", "ci")
	ciToken := strings.TrimSpace(out)
	if code != 0 || !auth.LooksLikeAPIToken(ciToken) {
		t.Fatalf("token create: %d %q", code, out)
	}
	code, out, _ = c.run("--output", "json", "token", "list")
	if code != 0 || !strings.Contains(out, `"name": "ci"`) || strings.Contains(out, ciToken) {
		t.Fatalf("token list: %d %s", code, out)
	}
	var ciID string
	if err := e.db.QueryRow(context.Background(), "SELECT id::text FROM api_tokens WHERE name = 'ci'").Scan(&ciID); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := c.run("token", "revoke", ciID); code != 0 {
		t.Fatalf("token revoke: %d", code)
	}
	if r := e.bearer(ciToken, http.MethodGet, "/api/v1/me", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("revoked CI token still works: %d", r.status)
	}

	// CI-style use through environment variables.
	ci := &cliRunner{t: t, env: map[string]string{"XDG_CONFIG_HOME": t.TempDir(), "NOOK_SERVER": e.base}}
	if code, _, _ := ci.run("whoami"); code != 1 {
		t.Fatal("whoami without a token should fail")
	}

	var cliToken string
	if err := e.db.QueryRow(context.Background(), "SELECT count(*)::text FROM api_tokens WHERE name LIKE 'CLI: %' AND revoked_at IS NULL").Scan(&cliToken); err != nil || cliToken != "1" {
		t.Fatalf("CLI token rows: %s %v", cliToken, err)
	}
	if code, out, _ := c.run("logout"); code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("logout: %d %s", code, out)
	}
	if n := e.count("SELECT count(*) FROM api_tokens WHERE name LIKE 'CLI: %' AND revoked_at IS NOT NULL"); n != 1 {
		t.Fatal("logout did not revoke the CLI token server-side")
	}
	if code, _, errOut := c.run("whoami"); code != 1 || !strings.Contains(errOut, "not logged in") {
		t.Fatalf("whoami after logout: %d %s", code, errOut)
	}
}

// TestNoSecretsInLogs runs every flow that handles a secret and then
// checks that none of those secrets appears in the server's logs.
func TestNoSecretsInLogs(t *testing.T) {
	e := startEnv(t)
	b := e.browser()
	b.signIn(testinfra.DexAlice)
	session := b.sessionCookie()
	csrf := b.csrf()

	created := b.postAPI("/api/v1/tokens", map[string]string{"name": "log-test"})
	var tok struct {
		Token string `json:"token"`
	}
	created.json(t, &tok)
	e.bearer(tok.Token, http.MethodGet, "/api/v1/me", nil)
	e.bearer("nook_pat_"+strings.Repeat("a", 52), http.MethodGet, "/api/v1/me", nil) // a wrong token is logged as a failure

	d := e.startDevice(t)
	b.postForm("/device/decision", url.Values{"user_code": {d.UserCode}, "decision": {"approve"}}, true)
	e.allowNextPoll()
	issued := e.poll(d.DeviceCode)
	var dt struct {
		AccessToken string `json:"access_token"`
	}
	issued.json(t, &dt)

	logs := e.logs.String()
	if !strings.Contains(logs, `"msg":"http request"`) {
		t.Fatal("no access logs captured")
	}
	secrets := map[string]string{
		"session cookie":     session,
		"csrf token":         csrf,
		"api token":          tok.Token,
		"device code":        d.DeviceCode,
		"device-flow token":  dt.AccessToken,
		"oidc client secret": shared.dex.ClientSecret,
		"dex password":       shared.dex.Passwords[testinfra.DexAlice],
	}
	for name, s := range secrets {
		if s == "" {
			t.Fatalf("%s was not captured", name)
		}
		if strings.Contains(logs, s) {
			t.Errorf("%s appears in the logs", name)
		}
	}
}
