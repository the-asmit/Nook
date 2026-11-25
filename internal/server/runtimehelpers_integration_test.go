//go:build integration

package server

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/builds"
	"github.com/the-asmit/nook/internal/testinfra"
)

// testApp is the one-layer image of testdata/testapp, built once.
var testApp struct {
	once  sync.Once
	layer []byte
	err   error
}

// testAppLayer compiles testdata/testapp statically and packs it as an
// image layer holding /testapp.
func testAppLayer(t *testing.T) []byte {
	t.Helper()
	testApp.once.Do(func() {
		dir, err := os.MkdirTemp("", "nook-testapp-")
		if err != nil {
			testApp.err = err
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()
		bin := filepath.Join(dir, "testapp")
		cmd := exec.CommandContext(context.Background(), "go", "build", "-trimpath", "-o", bin, ".") //nolint:gosec // G204: builds the test app from testdata.
		cmd.Dir = filepath.Join(testinfra.RepoRoot(), "internal", "server", "testdata", "testapp")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
		if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
			testApp.err = &buildError{out: string(out), err: buildErr}
			return
		}
		data, err := os.ReadFile(bin)
		if err != nil {
			testApp.err = err
			return
		}
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(&tar.Header{Name: "testapp", Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}); err != nil {
			testApp.err = err
			return
		}
		_, _ = tw.Write(data)
		_ = tw.Close()
		testApp.layer = buf.Bytes()
	})
	if testApp.err != nil {
		t.Fatalf("build the test app: %v", testApp.err)
	}
	return testApp.layer
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.out }

// pushTestApp pushes the test app image into an app's repository and
// returns its digest.
func pushTestApp(t *testing.T, repo string) string {
	t.Helper()
	return pushImage(t, repo, "fixture", testAppLayer(t), map[string]any{
		"Cmd": []string{"/testapp"}, "User": "65532:65532",
	})
}

// runtimeEnv is a control plane with one running agent that can build
// and run apps.
type runtimeEnv struct {
	*buildEnv
}

func startRuntimeEnv(t *testing.T, overrides map[string]string) *runtimeEnv {
	t.Helper()
	return &runtimeEnv{buildEnv: startBuildEnv(t, overrides)}
}

// startRuntimeEnvWith also configures the agent.
func startRuntimeEnvWith(t *testing.T, overrides, agentOverrides map[string]string) *runtimeEnv {
	t.Helper()
	return &runtimeEnv{buildEnv: startBuildEnvWith(t, overrides, agentOverrides)}
}

// appIDs returns an app's workspace and app IDs.
func (r *runtimeEnv) appIDs(ws, slug string) (wsID, appID uuid.UUID) {
	r.t.Helper()
	err := r.db.QueryRow(context.Background(),
		"SELECT a.workspace_id, a.id FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE w.slug = $1 AND a.slug = $2 AND a.deleted_at IS NULL",
		ws, slug).Scan(&wsID, &appID)
	if err != nil {
		r.t.Fatal(err)
	}
	return wsID, appID
}

// newRuntimeApp creates a running app for the test app image.
func (r *runtimeEnv) newRuntimeApp(u user, ws, slug string, extra map[string]any) {
	r.t.Helper()
	body := map[string]any{"slug": slug, "port": 8080, "health_check_path": "/healthz", "memory_mb": 64, "cpu_millicores": 100, "startup_timeout_seconds": 20}
	for k, v := range extra {
		body[k] = v
	}
	expectStatus(r.t, r.as(u, http.MethodPost, appsURL(ws), body), http.StatusCreated, "create app "+slug)
}

func appsURL(ws string) string { return "/api/v1/workspaces/" + ws + "/apps" }

// release records a built deployment of the test app image (as if a build
// had produced it) and queues it, returning its number.
func (r *runtimeEnv) release(ws, slug string) int32 {
	r.t.Helper()
	wsID, appID := r.appIDs(ws, slug)
	digest := pushTestApp(r.t, apps.RepositoryName(wsID, appID))
	ctx := context.Background()
	var id uuid.UUID
	var n int32
	sum := sha256.Sum256([]byte("fixture"))
	err := r.db.QueryRow(ctx, `
		WITH n AS (
			UPDATE apps SET next_deployment_number = next_deployment_number + 1 WHERE id = $1
			RETURNING next_deployment_number - 1 AS number
		)
		INSERT INTO deployments (app_id, number, status, source_key, source_sha256, source_size, upload_expires_at,
		                         source_deleted_at, image_digest, built_at)
		SELECT $1, n.number, 'built', 'fixture', $2, 1, now(), now(), $3, now() FROM n
		RETURNING id, number`, appID, sum[:], digest).Scan(&id, &n)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := builds.NewQueue(redisClient(r.t)).Enqueue(ctx, id); err != nil {
		r.t.Fatal(err)
	}
	return n
}

// waitLive waits for a deployment to go live and fails the test otherwise.
func (r *runtimeEnv) waitLive(u user, ws, slug string, n int32) {
	r.t.Helper()
	d := r.waitStatus(u, ws, slug, n, 3*time.Minute, "live", "failed", "superseded")
	if d.Status != "live" {
		r.t.Fatalf("deployment #%d is %s: %s\nlog:\n%s\nserver logs:\n%s", n, d.Status, d.FailureReason, r.buildLog(u, ws, slug, n), r.logs.String())
	}
}

// appState is GET /apps/{app}.
type appState struct {
	DesiredState   string `json:"desired_state"`
	LiveDeployment *int32 `json:"live_deployment"`
	Health         string `json:"health"`
	Instance       *struct {
		Node         string `json:"node"`
		State        string `json:"state"`
		Address      string `json:"address"`
		HostPort     *int32 `json:"host_port"`
		RestartCount int32  `json:"restart_count"`
		LastError    string `json:"last_error"`
	} `json:"instance"`
}

func (r *runtimeEnv) app(u user, ws, slug string) appState {
	r.t.Helper()
	var a appState
	res := r.as(u, http.MethodGet, appURL(ws, slug), nil)
	if res.status != http.StatusOK {
		r.t.Fatalf("get app: %d %s", res.status, res.body)
	}
	res.json(r.t, &a)
	return a
}

// appBase is where the app's live instance is published.
func (r *runtimeEnv) appBase(u user, ws, slug string) string {
	r.t.Helper()
	a := r.app(u, ws, slug)
	if a.Instance == nil || a.Instance.HostPort == nil {
		r.t.Fatalf("app %s has no published instance: %+v", slug, a)
	}
	return "http://" + a.Instance.Address + ":" + strconv.Itoa(int(*a.Instance.HostPort))
}

// get fetches a URL and returns status and body ("" and 0 on errors).
func get(url string) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body)
}

// setEnv sets variables through the API and returns the response.
func (r *runtimeEnv) setEnv(u user, ws, slug string, vars map[string]string, secret bool) response {
	r.t.Helper()
	return r.as(u, http.MethodPut, appURL(ws, slug)+"/env", map[string]any{"vars": vars, "secret": secret})
}

// envDeployment is the deployment an env change created.
func envDeployment(t *testing.T, res response) int32 {
	t.Helper()
	var out struct {
		Deployment *struct {
			Number int32  `json:"number"`
			Kind   string `json:"kind"`
		} `json:"deployment"`
	}
	if err := json.Unmarshal([]byte(res.body), &out); err != nil || out.Deployment == nil {
		t.Fatalf("env change created no deployment: %d %s", res.status, res.body)
	}
	if out.Deployment.Kind != "config" {
		t.Fatalf("env deployment kind %q", out.Deployment.Kind)
	}
	return out.Deployment.Number
}
