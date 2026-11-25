//go:build integration

package server

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// TestFollowerOnAnotherInstanceGetsLiveLines: the agent is connected to
// instance A, the follower reads the log through instance B.
func TestFollowerOnAnotherInstanceGetsLiveLines(t *testing.T) {
	b := startBuildEnv(t, nil) // agent on the primary (A)
	other := b.startInstance(map[string]string{"NOOK_HTTP_ADDR": "127.0.0.1:0"})
	b.createApp(b.alice, b.ws, "web")
	n := b.deploy(b.alice, b.ws, "web", project(t, slowDockerfile("cross-instance-marker", 5)))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		other.base+appURL(b.ws, "web")+"/deployments/"+itoa(n)+"/build-log?follow=1", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+b.alice.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("follow: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	events := map[string]int{}
	var sawMarker, sawBuilding bool
	sc := bufio.NewScanner(resp.Body)
	var event string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
			events[event]++
		case strings.HasPrefix(line, "data: "):
			data := strings.TrimPrefix(line, "data: ")
			if event == "line" && strings.Contains(data, "cross-instance-marker") {
				sawMarker = true
			}
			if event == "status" && strings.Contains(data, "building") {
				sawBuilding = true
			}
			if event == "end" {
				if !strings.Contains(data, `"status":"built"`) {
					t.Fatalf("end event %s", data)
				}
				if !sawMarker || !sawBuilding || events["line"] < 5 {
					t.Fatalf("events %v marker %v building %v", events, sawMarker, sawBuilding)
				}
				return
			}
		}
	}
	t.Fatalf("stream ended without an end event (%v): %v", events, sc.Err())
}

func TestUploadIsVerifiedAndScoped(t *testing.T) {
	b := startQueueOnly(t, nil)
	mallory := b.newUser("mallory@nook.test")
	b.createApp(b.alice, b.ws, "web")
	dir := project(t, helloDockerfile("verify"))
	data, c := b.startDeploy(b.alice, b.ws, "web", dir)
	confirm := appURL(b.ws, "web") + "/deployments/1/upload-complete"

	if r := b.as(b.alice, http.MethodPost, confirm, nil); r.status != http.StatusConflict || r.errorCode(t) != "upload_missing" {
		t.Fatalf("confirm before upload: %d %s", r.status, r.body)
	}
	tampered := bytes.Clone(data)
	tampered[len(tampered)/2] ^= 0xff
	if code := upload(t, &c, tampered); code < 400 {
		t.Fatalf("storage accepted different content: HTTP %d", code)
	}
	if code := upload(t, &c, data[:len(data)-1]); code < 400 {
		t.Fatalf("storage accepted a shorter body: HTTP %d", code)
	}
	if r := b.as(b.alice, http.MethodPost, confirm, nil); r.errorCode(t) != "upload_missing" {
		t.Fatalf("after rejected uploads: %d %s", r.status, r.body)
	}
	if code := upload(t, &c, data); code != http.StatusOK {
		t.Fatalf("upload: HTTP %d", code)
	}
	// Another tenant can neither confirm nor see the deployment.
	for _, req := range []struct{ method, path string }{
		{http.MethodPost, confirm},
		{http.MethodGet, appURL(b.ws, "web") + "/deployments/1"},
		{http.MethodGet, appURL(b.ws, "web") + "/deployments/1/build-log"},
		{http.MethodPost, appURL(b.ws, "web") + "/deployments/1/cancel"},
	} {
		expectStatus(t, b.as(mallory, req.method, req.path, nil), http.StatusNotFound, "mallory "+req.method+" "+req.path)
	}
	expectStatus(t, b.as(b.alice, http.MethodPost, confirm, nil), http.StatusOK, "confirm")
	if r := b.as(b.alice, http.MethodPost, confirm, nil); r.status != http.StatusConflict {
		t.Fatalf("confirming twice: %d", r.status)
	}
	// The announced size is bounded.
	r := b.as(b.alice, http.MethodPost, appURL(b.ws, "web")+"/deployments", map[string]any{
		"source_size": 300 << 20, "source_sha256": strings.Repeat("ab", 32),
	})
	if r.status != http.StatusBadRequest || r.errorCode(t) != "source_too_large" {
		t.Fatalf("oversized source: %d %s", r.status, r.body)
	}
}

// TestAppsTenantIsolationAndRoles: non-members get 404 for every app
// endpoint; members may create and deploy but not delete.
func TestAppsTenantIsolationAndRoles(t *testing.T) {
	b := startQueueOnly(t, nil)
	mallory := b.newUser("mallory@nook.test")
	bob := b.newUser("bob@nook.test")
	expectStatus(t, b.as(b.alice, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Acme", "slug": "acme"}), 201, "create workspace")
	b.addMember("acme", bob, "member")
	b.createApp(b.alice, "acme", "web")

	for _, req := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/workspaces/acme/apps", nil},
		{http.MethodPost, "/api/v1/workspaces/acme/apps", map[string]any{"slug": "x"}},
		{http.MethodGet, appURL("acme", "web"), nil},
		{http.MethodDelete, appURL("acme", "web"), nil},
		{http.MethodGet, appURL("acme", "web") + "/deployments", nil},
		{http.MethodPost, appURL("acme", "web") + "/deployments", map[string]any{"source_size": 10, "source_sha256": strings.Repeat("ab", 32)}},
	} {
		expectStatus(t, b.as(mallory, req.method, req.path, req.body), http.StatusNotFound, "mallory "+req.method+" "+req.path)
	}
	expectStatus(t, b.as(bob, http.MethodPost, "/api/v1/workspaces/acme/apps", map[string]any{"slug": "bobs-app"}), 201, "member creates")
	n := b.deploy(bob, "acme", "bobs-app", project(t, helloDockerfile("bob")))
	if d := b.deployment(bob, "acme", "bobs-app", n); d.Status != "queued" {
		t.Fatalf("member deploy: %+v", d)
	}
	expectStatus(t, b.as(bob, http.MethodDelete, appURL("acme", "web"), nil), http.StatusForbidden, "member deletes")
	expectStatus(t, b.as(b.alice, http.MethodDelete, appURL("acme", "bobs-app"), nil), http.StatusNoContent, "owner deletes")
	expectStatus(t, b.as(bob, http.MethodGet, appURL("acme", "bobs-app"), nil), http.StatusNotFound, "deleted app")
	// The deleted app's queued deployment was canceled.
	var status string
	if err := b.db.QueryRow(context.Background(), "SELECT status::text FROM deployments d JOIN apps a ON a.id = d.app_id WHERE a.slug = 'bobs-app'").Scan(&status); err != nil || status != statusCancelled {
		t.Fatalf("deployment of deleted app: %s %v", status, err)
	}
	// The workspace cannot be deleted while it has apps.
	if r := b.as(b.alice, http.MethodDelete, "/api/v1/workspaces/acme", nil); r.status != http.StatusConflict || r.errorCode(t) != "workspace_has_apps" {
		t.Fatalf("delete workspace with apps: %d %s", r.status, r.body)
	}
	expectStatus(t, b.as(b.alice, http.MethodPost, "/api/v1/workspaces/acme/apps", map[string]any{"slug": "Bad Slug"}), 400, "invalid slug")
	expectStatus(t, b.as(b.alice, http.MethodPost, "/api/v1/workspaces/acme/apps", map[string]any{"slug": "web"}), 409, "duplicate slug")
	expectStatus(t, b.as(b.alice, http.MethodPost, "/api/v1/workspaces/acme/apps", map[string]any{"slug": "big", "memory_mb": 1 << 20}), 400, "memory above the maximum")
}

func TestQuotas(t *testing.T) {
	b := startQueueOnly(t, nil)
	bob := b.newUser("bob@nook.test")
	quota := "/api/v1/admin/workspaces/" + bob.personal + "/quota"
	expectStatus(t, b.as(bob, http.MethodGet, quota, nil), http.StatusForbidden, "non-admin reads quota")
	var q struct {
		MaxApps int  `json:"max_apps"`
		Default bool `json:"default"`
	}
	b.as(b.alice, http.MethodGet, quota, nil).json(t, &q)
	if q.MaxApps != 20 || !q.Default {
		t.Fatalf("default quota %+v", q)
	}
	expectStatus(t, b.as(b.alice, http.MethodPut, quota, map[string]int{"max_apps": 1, "max_concurrent_builds": 0}), 200, "set quota")
	b.createApp(bob, bob.personal, "one")
	r := b.as(bob, http.MethodPost, "/api/v1/workspaces/"+bob.personal+"/apps", map[string]any{"slug": "two"})
	if r.status != http.StatusConflict || r.errorCode(t) != "quota_exceeded" {
		t.Fatalf("second app: %d %s", r.status, r.body)
	}
	if !strings.Contains(strings.Join(b.auditActions(), ","), "quota.update") {
		t.Fatal("quota change not audited")
	}
}

func TestBuildTimeLimit(t *testing.T) {
	b := startBuildEnv(t, map[string]string{"NOOK_BUILD_TIMEOUT": "15s"})
	b.createApp(b.alice, b.ws, "slow")
	n := b.deploy(b.alice, b.ws, "slow", project(t, slowDockerfile("forever", 600)))
	d := b.waitStatus(b.alice, b.ws, "slow", n, 3*time.Minute, "failed", "built")
	if d.Status != "failed" || !strings.Contains(d.FailureReason, "time limit") || len(d.Builds) != 1 || *d.Builds[0].Result != "timed_out" {
		t.Fatalf("deployment %+v", d)
	}
}

func TestDuplicateJobsBuildOnce(t *testing.T) {
	b := startBuildEnv(t, nil)
	b.createApp(b.alice, b.ws, "web")
	n := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile("dup")))
	var id string
	if err := b.db.QueryRow(context.Background(), "SELECT id::text FROM deployments WHERE number = $1", n).Scan(&id); err != nil {
		t.Fatal(err)
	}
	rdb := redisClient(t)
	for range 3 {
		if err := rdb.XAdd(context.Background(), &goredis.XAddArgs{Stream: "nook:builds:queue", Values: map[string]any{"d": id}}).Err(); err != nil {
			t.Fatal(err)
		}
	}
	b.waitStatus(b.alice, b.ws, "web", n, 3*time.Minute, "built")
	if b.count("SELECT count(*) FROM builds") != 1 {
		t.Fatal("duplicate jobs built twice")
	}
}

// TestSecretsStayOutOfLogs checks the server and agent logs of a full
// build for presigned URLs and registry tokens.
func TestSecretsStayOutOfLogs(t *testing.T) {
	b := startQueueOnly(t, nil)
	var agentLogs syncBuffer
	token, caHash := b.joinToken(b.alice, nil)
	state := joinAgent(t, b.primary.grpc, token, caHash, "builder-1")
	runAgentWith(t, state, slog.New(slog.NewJSONHandler(&agentLogs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	eventually(t, 30*time.Second, "node ready", func() bool { return b.nodeStatus(b.alice, "builder-1") == "ready" })
	b.createApp(b.alice, b.ws, "web")
	n := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile("secret")))
	b.waitStatus(b.alice, b.ws, "web", n, 3*time.Minute, "built")
	log := b.buildLog(b.alice, b.ws, "web", n)
	for name, text := range map[string]string{"server": b.logs.String(), "agent": agentLogs.String(), "build log": log} {
		for _, secret := range []string{"X-Amz-Signature", "X-Amz-Credential", shared.storage.MinIO.SecretKey, "registrytoken", "eyJ"} {
			if strings.Contains(text, secret) {
				t.Errorf("%s logs contain %q", name, secret)
			}
		}
	}
}

// addMember adds u to a workspace directly (invitations are tested elsewhere).
func (b *buildEnv) addMember(slug string, u user, role string) {
	b.t.Helper()
	b.exec(`INSERT INTO memberships (workspace_id, user_id, role)
		SELECT id, $2, $3::workspace_role FROM workspaces WHERE slug = $1`, slug, u.id, role)
}
