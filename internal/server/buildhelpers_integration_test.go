//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/archive"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/store"
)

// statusCancelled is the API status of a canceled deployment.
const statusCancelled = string(store.DeploymentStatusCancelled)

// buildEnv is a control plane with one joined, running build agent.
type buildEnv struct {
	*env
	alice user
	ws    string
	agent *runningAgent
}

func startBuildEnv(t *testing.T, overrides map[string]string) *buildEnv {
	t.Helper()
	e := startEnvWith(t, overrides)
	alice := e.adminAlice()
	b := &buildEnv{env: e, alice: alice, ws: alice.personal}
	b.agent = b.joinBuilder("builder-1", e.primary.grpc)
	return b
}

// joinBuilder joins and runs an agent and waits until its node is ready.
func (b *buildEnv) joinBuilder(name, grpcAddr string) *runningAgent {
	b.t.Helper()
	token, caHash := b.joinToken(b.alice, nil)
	a := runAgent(b.t, joinAgent(b.t, grpcAddr, token, caHash, name))
	eventually(b.t, 30*time.Second, name+" ready", func() bool { return b.nodeStatus(b.alice, name) == "ready" })
	return a
}

// project writes files into a new folder.
func project(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func (b *buildEnv) createApp(u user, ws, slug string) {
	b.t.Helper()
	expectStatus(b.t, b.as(u, http.MethodPost, "/api/v1/workspaces/"+ws+"/apps", map[string]any{"slug": slug}), http.StatusCreated, "create app "+slug)
}

func appURL(ws, app string) string { return "/api/v1/workspaces/" + ws + "/apps/" + app }

type deploymentResp struct {
	Number          int32   `json:"number"`
	Status          string  `json:"status"`
	ImageDigest     *string `json:"image_digest"`
	Image           *string `json:"image"`
	FailureReason   string  `json:"failure_reason"`
	CancelRequested bool    `json:"cancel_requested"`
	ImageDeleted    bool    `json:"image_deleted"`
	Builds          []struct {
		Attempt int32   `json:"attempt"`
		Node    string  `json:"node"`
		Result  *string `json:"result"`
		Message string  `json:"message"`
	} `json:"builds"`
}

type createResp struct {
	Deployment deploymentResp `json:"deployment"`
	Upload     struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
	} `json:"upload"`
}

// startDeploy packs dir and creates a deployment for it, returning the
// archive and the upload instructions.
func (b *buildEnv) startDeploy(u user, ws, app, dir string) ([]byte, createResp) {
	b.t.Helper()
	var buf bytes.Buffer
	res, err := archive.Pack(dir, &buf, archive.PackOptions{})
	if err != nil {
		b.t.Fatal(err)
	}
	r := b.as(u, http.MethodPost, appURL(ws, app)+"/deployments", map[string]any{
		"source_size": res.Size, "source_sha256": hex.EncodeToString(res.SHA256),
	})
	var out createResp
	r.json(b.t, &out)
	if r.status != http.StatusCreated {
		b.t.Fatalf("create deployment: %d %s", r.status, r.body)
	}
	return buf.Bytes(), out
}

// upload sends body to a presigned upload and returns the storage status.
func upload(t *testing.T, c *createResp, body []byte) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), c.Upload.Method, c.Upload.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range c.Upload.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// deploy packs, uploads and confirms; it returns the deployment number.
func (b *buildEnv) deploy(u user, ws, app, dir string) int32 {
	b.t.Helper()
	data, c := b.startDeploy(u, ws, app, dir)
	if code := upload(b.t, &c, data); code != http.StatusOK {
		b.t.Fatalf("upload: HTTP %d", code)
	}
	expectStatus(b.t, b.as(u, http.MethodPost, appURL(ws, app)+"/deployments/"+itoa(c.Deployment.Number)+"/upload-complete", nil), http.StatusOK, "confirm")
	return c.Deployment.Number
}

func itoa(n int32) string { return strconv.Itoa(int(n)) }

func (b *buildEnv) deployment(u user, ws, app string, n int32) deploymentResp {
	b.t.Helper()
	var d deploymentResp
	b.as(u, http.MethodGet, appURL(ws, app)+"/deployments/"+itoa(n), nil).json(b.t, &d)
	return d
}

// waitStatus waits until the deployment has one of the statuses.
func (b *buildEnv) waitStatus(u user, ws, app string, n int32, within time.Duration, statuses ...string) deploymentResp {
	b.t.Helper()
	var d deploymentResp
	eventually(b.t, within, "deployment #"+itoa(n)+" to be "+strings.Join(statuses, "/"), func() bool {
		d = b.deployment(u, ws, app, n)
		for _, s := range statuses {
			if d.Status == s {
				return true
			}
		}
		return false
	})
	return d
}

func (b *buildEnv) buildLog(u user, ws, app string, n int32) string {
	b.t.Helper()
	return b.as(u, http.MethodGet, appURL(ws, app)+"/deployments/"+itoa(n)+"/build-log", nil).body
}

// registryClient talks to the shared registry as the control plane does.
func registryClient(t *testing.T) *registry.Client {
	t.Helper()
	ca, _, err := pki.LoadOrCreateCA(shared.caPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &registry.Config{Addr: shared.storage.Registry.Addr, Service: "nook-registry", Issuer: "nook", RequestTimeout: 30 * time.Second}
	return registry.NewClient(cfg, registry.NewIssuer(ca, "nook", "nook-registry"), ca)
}

// helloDockerfile builds quickly and prints marker in its log.
func helloDockerfile(marker string) map[string]string {
	return map[string]string{
		"Dockerfile": "FROM alpine:3.23\nCOPY marker.txt /marker.txt\nRUN cat /marker.txt\n",
		"marker.txt": marker + "\n",
	}
}

// slowDockerfile runs long enough to be caught building.
func slowDockerfile(marker string, seconds int) map[string]string {
	return map[string]string{
		"Dockerfile": "FROM alpine:3.23\nCOPY marker.txt /marker.txt\nRUN cat /marker.txt && sleep " + strconv.Itoa(seconds) + "\n",
		"marker.txt": marker + "\n",
	}
}
