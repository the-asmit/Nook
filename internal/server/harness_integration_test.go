//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"

	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/logging"
	"github.com/the-asmit/nook/internal/testinfra"
)

// shared holds the dependencies started once for the whole package. Tests
// run sequentially and each gets a fresh database and a flushed Redis.
var shared struct {
	pgAdminURL string
	redisURL   string
	dex        *testinfra.Dex
	// serverPort is fixed because it is registered with Dex as the
	// redirect URI before any server starts.
	serverPort int
	// gatewayPort is fixed for the same reason: the auth host's callback
	// (http://auth.apps.localhost:<port>/callback) is registered with Dex.
	gatewayPort int
	// caPath is the agent CA shared by every instance in this package.
	caPath string
	// storage is MinIO and the image registry (TLS from the shared CA).
	storage *testinfra.StorageT
}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(runIntegration(m))
}

func runIntegration(m *testing.M) int {
	ctx := context.Background()
	pg, pgURL, err := testinfra.StartPostgres(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(pg) }()
	rd, redisURL, err := testinfra.StartRedis(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(rd) }()

	serverPort, err := testinfra.FreePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dexPort, err := testinfra.FreePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	gatewayPort, err := testinfra.FreePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dex, dexC, err := testinfra.StartDex(ctx, dexPort, fmt.Sprintf("http://127.0.0.1:%d/auth/callback", serverPort),
		fmt.Sprintf("http://auth.apps.localhost:%d/callback", gatewayPort))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(dexC) }()

	caDir, err := os.MkdirTemp("", "nook-ca-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(caDir) }()

	shared.pgAdminURL, shared.redisURL, shared.dex, shared.serverPort = pgURL, redisURL, dex, serverPort
	shared.gatewayPort = gatewayPort
	shared.caPath = filepath.Join(caDir, "ca.pem")

	// The registry's certificate comes from the same CA the control plane
	// uses, as in a real installation.
	ca, _, err := pki.LoadOrCreateCA(shared.caPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cert, err := ca.IssueServerCertificate([]string{testinfra.RegistryAlias, "localhost", "127.0.0.1"}, 24*time.Hour)
	if err == nil {
		err = ca.WriteServerFiles(filepath.Join(caDir, "registry"), cert)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	storage, stopStorage, err := testinfra.StartStorage(ctx, filepath.Join(caDir, "registry"), "nook")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer stopStorage()
	shared.storage = storage
	return m.Run()
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// env is one running nook-server with its own database.
type env struct {
	t     *testing.T
	base  string
	db    *pgxpool.Pool
	dbURL string
	logs  *syncBuffer
	// primary is the first instance (the one at base).
	primary *instance
}

// instance is one running control-plane process.
type instance struct {
	srv  *Server
	base string
	grpc string
	logs *syncBuffer
	stop func()
}

// baseEnviron returns a development configuration for the shared stack.
func baseEnviron(pgURL string) map[string]string {
	return map[string]string{
		"NOOK_ENV":                    "development",
		"NOOK_LOG_LEVEL":              "debug",
		"NOOK_HTTP_ADDR":              "127.0.0.1:" + strconv.Itoa(shared.serverPort),
		"NOOK_PUBLIC_URL":             "http://127.0.0.1:" + strconv.Itoa(shared.serverPort),
		"NOOK_POSTGRES_URL":           pgURL,
		"NOOK_REDIS_URL":              shared.redisURL,
		"NOOK_OIDC_ISSUER_URL":        shared.dex.IssuerURL,
		"NOOK_OIDC_CLIENT_ID":         shared.dex.ClientID,
		"NOOK_OIDC_CLIENT_SECRET":     shared.dex.ClientSecret,
		"NOOK_ALLOWED_EMAIL_DOMAINS":  "nook.test",
		"NOOK_BOOTSTRAP_ADMIN_EMAILS": testinfra.DexAlice,
		"NOOK_DEVICE_POLL_INTERVAL":   "1s",
		// Worker nodes, with timings shortened so tests run quickly.
		"NOOK_PKI_CA_PATH":                shared.caPath,
		"NOOK_GRPC_ADDR":                  "127.0.0.1:0",
		"NOOK_HEARTBEAT_INTERVAL":         "1s",
		"NOOK_NODE_DEAD_AFTER":            "4s",
		"NOOK_HEARTBEAT_PERSIST_INTERVAL": "1s",
		"NOOK_FAILURE_DETECTOR_INTERVAL":  "200ms",
		"NOOK_LEADER_RETRY_INTERVAL":      "300ms",
		"NOOK_NODE_COMMAND_TIMEOUT":       "2s",
		// Apps and builds, with short timings.
		"NOOK_S3_ENDPOINT":            shared.storage.MinIO.URL,
		"NOOK_S3_BUCKET":              "nook",
		"NOOK_S3_ACCESS_KEY_ID":       shared.storage.MinIO.AccessKey,
		"NOOK_S3_SECRET_ACCESS_KEY":   shared.storage.MinIO.SecretKey,
		"NOOK_REGISTRY_ADDR":          shared.storage.Registry.NetworkAddr,
		"NOOK_REGISTRY_URL":           "https://" + shared.storage.Registry.Addr,
		"NOOK_REGISTRY_GC_SECRET":     testGCSecret,
		"NOOK_BUILD_TICK_INTERVAL":    "200ms",
		"NOOK_BUILD_CLAIM_TIMEOUT":    "3s",
		"NOOK_BUILD_ACCEPT_TIMEOUT":   "10s",
		"NOOK_BUILD_TIMEOUT":          "5m",
		"NOOK_BUILD_JANITOR_INTERVAL": "24h",
		"NOOK_BUILD_QUEUE_TIMEOUT":    "10m",
		// Running apps, with short timings.
		"NOOK_SECRETS_KEY":          testSecretsKey,
		"NOOK_ROLLOUT_DRAIN":        "1s",
		"NOOK_ROLLOUT_PULL_TIMEOUT": "2m",
		// The gateway's apps domain and shared secret.
		"NOOK_APPS_BASE_URL":     appsBaseURL(),
		"NOOK_GATEWAY_SECRET":    testGatewaySecret,
		"NOOK_ALLOW_PUBLIC_APPS": "true",
	}
}

// appsBaseURL is the apps domain the test gateway serves.
func appsBaseURL() string { return "http://apps.localhost:" + strconv.Itoa(shared.gatewayPort) }

// testGCSecret authenticates the registry GC job in tests.
const testGCSecret = "test-gc-secret-0123456789"

// startEnv runs a server on a fresh database.
func startEnv(t *testing.T) *env {
	t.Helper()
	return startEnvWith(t, nil)
}

// startEnvWith is startEnv with configuration overrides for the primary
// instance.
func startEnvWith(t *testing.T, overrides map[string]string) *env {
	t.Helper()
	dbURL := testinfra.CreateDatabase(t, shared.pgAdminURL)
	flushRedis(t)
	db, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e := &env{t: t, db: db, dbURL: dbURL}
	e.primary = e.startInstance(overrides)
	e.base, e.logs = e.primary.base, e.primary.logs
	return e
}

// startInstance starts another control-plane instance on the env's
// database; overrides adjust its configuration.
func (e *env) startInstance(overrides map[string]string) *instance {
	t := e.t
	t.Helper()
	environ := baseEnviron(e.dbURL)
	for k, v := range overrides {
		environ[k] = v
	}
	cfg, err := config.Load[Config](environ)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger, err := logging.New(logs, cfg.Log)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(context.Background(), &cfg, logger)
	if err != nil {
		t.Fatalf("New() = %v\nlogs:\n%s", err, logs.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("Serve() = %v", err)
			}
			srv.Close()
		})
	}
	t.Cleanup(stop)
	return &instance{srv: srv, base: "http://" + srv.Addr().String(), grpc: srv.GRPCAddr().String(), logs: logs, stop: stop}
}

// redisClient returns a client for the shared Redis, closed after the test.
func redisClient(t *testing.T) *goredis.Client {
	t.Helper()
	opts, err := goredis.ParseURL(shared.redisURL)
	if err != nil {
		t.Fatal(err)
	}
	c := goredis.NewClient(opts)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func flushRedis(t *testing.T) {
	t.Helper()
	c := redisClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.FlushDB(ctx).Err(); err != nil {
		t.Fatal(err)
	}
}

// count runs a SELECT count(*)-style query against the env's database.
func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

// exec runs a statement against the env's database.
func (e *env) exec(query string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(context.Background(), query, args...); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
}

// auditActions returns the audit log's actions in order.
func (e *env) auditActions() []string {
	e.t.Helper()
	rows, err := e.db.Query(context.Background(), "SELECT action FROM audit_log ORDER BY id")
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// response is a completed HTTP exchange.
type response struct {
	status int
	header http.Header
	body   string
	url    *url.URL
}

func (r response) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.body), v); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
}

// errorCode extracts error.code from an error envelope.
func (r response) errorCode(t *testing.T) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	r.json(t, &env)
	return env.Error.Code
}

func send(t *testing.T, c *http.Client, req *http.Request) response {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: string(b), url: resp.Request.URL}
}

func newRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func jsonBody(t *testing.T, v any) io.Reader {
	t.Helper()
	if v == nil {
		return http.NoBody
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

// bearer calls the API with an API token.
func (e *env) bearer(token, method, path string, body any) response {
	e.t.Helper()
	req := newRequest(e.t, method, e.base+path, jsonBody(e.t, body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return send(e.t, http.DefaultClient, req)
}

// browser is a cookie-carrying HTTP client that behaves like a web browser.
type browser struct {
	e   *env
	jar *cookiejar.Jar
	c   *http.Client
}

func (e *env) browser() *browser {
	e.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return &browser{e: e, jar: jar, c: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

var formAction = regexp.MustCompile(`<form[^>]+action="([^"]+)"`)

// openDexForm starts a sign-in and returns the Dex login form's URL.
func (b *browser) openDexForm() *url.URL {
	t := b.e.t
	t.Helper()
	r := send(t, b.c, newRequest(t, http.MethodGet, b.e.base+"/auth/login?return_to=/", http.NoBody))
	m := formAction.FindStringSubmatch(r.body)
	if r.status != http.StatusOK || m == nil {
		t.Fatalf("no Dex login form (status %d at %s): %.300s", r.status, r.url, r.body)
	}
	action, err := r.url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// submitDex posts credentials to Dex and follows redirects back to Nook.
func (b *browser) submitDex(action *url.URL, email string) response {
	t := b.e.t
	t.Helper()
	form := url.Values{"login": {email}, "password": {shared.dex.Passwords[email]}}
	req := newRequest(t, http.MethodPost, action.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return send(t, b.c, req)
}

// signIn performs the complete browser sign-in through Dex.
func (b *browser) signIn(email string) response {
	b.e.t.Helper()
	return b.submitDex(b.openDexForm(), email)
}

// sessionCookie returns the session cookie value, or "".
func (b *browser) sessionCookie() string {
	u, _ := url.Parse(b.e.base)
	for _, c := range b.jar.Cookies(u) {
		if c.Name == "nook_session" {
			return c.Value
		}
	}
	return ""
}

func (b *browser) setSessionCookie(value string) {
	u, _ := url.Parse(b.e.base)
	b.jar.SetCookies(u, []*http.Cookie{{Name: "nook_session", Value: value, Path: "/"}})
}

// csrf returns the session's CSRF token from /api/v1/me.
func (b *browser) csrf() string {
	t := b.e.t
	t.Helper()
	r := b.api(http.MethodGet, "/api/v1/me", nil, nil)
	var me struct {
		CSRFToken string `json:"csrf_token"`
	}
	r.json(t, &me)
	if me.CSRFToken == "" {
		t.Fatalf("no CSRF token: %s", r.body)
	}
	return me.CSRFToken
}

// api calls the JSON API with the session cookie. Unless headers say
// otherwise, it sends the same-origin Origin header and the CSRF token, as
// the dashboard would.
func (b *browser) api(method, path string, body any, headers map[string]string) response {
	t := b.e.t
	t.Helper()
	req := newRequest(t, method, b.e.base+path, jsonBody(t, body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return send(t, b.c, req)
}

// postAPI sends a POST to the API the way the dashboard would: with the
// same-origin Origin header and the session's CSRF token.
func (b *browser) postAPI(path string, body any) response {
	b.e.t.Helper()
	return b.api(http.MethodPost, path, body, map[string]string{"Origin": b.e.base, "X-CSRF-Token": b.csrf()})
}

// postForm submits an HTML form with the session's CSRF token.
func (b *browser) postForm(path string, values url.Values, withCSRF bool) response {
	t := b.e.t
	t.Helper()
	if withCSRF {
		values.Set("csrf_token", b.csrf())
	}
	req := newRequest(t, http.MethodPost, b.e.base+path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.e.base)
	return send(t, b.c, req)
}
