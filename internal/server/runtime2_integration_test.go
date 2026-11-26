//go:build integration

package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/scheduler"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
)

// TestReconciliationAfterAgentRestart: while the agent is down, the app's
// container disappears and a stray Nook container shows up. When the
// agent is back, the control plane has the stray removed and the missing
// instance started again.
func TestReconciliationAfterAgentRestart(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	_, appID := r.appIDs(r.ws, "web")
	nodeID := r.agent.NodeID()

	r.agent.stop()
	if ok, _ := r.agent.exited(15 * time.Second); !ok {
		t.Fatal("agent did not stop")
	}
	ctx := context.Background()
	d := dockerClient(t)
	list, err := d.ContainerList(ctx, client.ContainerListOptions{Filters: client.Filters{}.Add("label", "nook.app="+appID.String())})
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("app containers: %v", err)
	}
	if _, err = d.ContainerRemove(ctx, list.Items[0].ID, client.ContainerRemoveOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	strayID := uuid.NewV7().String()
	stray, err := d.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: "nook-app-" + strayID,
		Config: &container.Config{Image: standInImage, Cmd: []string{"sleep", "600"}, Labels: map[string]string{
			"nook.managed": "true", "nook.node": nodeID, "nook.instance": strayID, "nook.app": appID.String(),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ContainerStart(ctx, stray.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}

	cfg := agentConfigWith(t, r.agentState, nil)
	runConfiguredAgent(t, &cfg, quietLogger)
	eventually(t, time.Minute, "the stray container to be removed", func() bool {
		_, err := d.ContainerInspect(ctx, stray.ID, client.ContainerInspectOptions{})
		return err != nil
	})
	eventually(t, time.Minute, "the missing instance to run again", func() bool {
		// The instance is placed again (its node was dead meanwhile); it
		// has a published port once it runs.
		if r.app(r.alice, r.ws, "web").Health != "running" {
			return false
		}
		code, _ := get(r.appBase(r.alice, r.ws, "web") + "/healthz")
		return code == http.StatusOK && countContainers(t, "nook.app="+appID.String()) == 1
	})
}

// sseLines follows an SSE endpoint on base and sends each data line.
func sseLines(t *testing.T, ctx context.Context, base, token, path string) <-chan string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // closed by the reading goroutine.
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("logs: %d %s", resp.StatusCode, body)
	}
	out := make(chan string, 100)
	go func() {
		defer close(out)
		defer func() { _ = resp.Body.Close() }()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			select {
			case out <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// waitLine reads lines until one contains want.
func waitLine(t *testing.T, lines <-chan string, want string, within time.Duration) {
	t.Helper()
	timer := time.NewTimer(within)
	defer timer.Stop()
	var seen []string
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("stream ended without %q:\n%s", want, strings.Join(seen, "\n"))
			}
			seen = append(seen, l)
			if strings.Contains(l, want) {
				return
			}
		case <-timer.C:
			t.Fatalf("no %q within %s:\n%s", want, within, strings.Join(seen, "\n"))
		}
	}
}

// TestLogsFollowAcrossInstances: the agent is connected to one control-
// plane instance, the client follows the app's logs through another and
// sees requests as they happen.
func TestLogsFollowAcrossInstances(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	other := r.startInstance(map[string]string{"NOOK_HTTP_ADDR": "127.0.0.1:0"})
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	base := r.appBase(r.alice, r.ws, "web")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The retained output first (no follow): the startup line.
	past := sseLines(t, ctx, other.base, r.alice.token, appURL(r.ws, "web")+"/logs?tail=50")
	waitLine(t, past, "testapp starting", 30*time.Second)
	waitLine(t, past, "event: end", 30*time.Second)

	live := sseLines(t, ctx, other.base, r.alice.token, appURL(r.ws, "web")+"/logs?follow=1&tail=0")
	// Requests until one is seen: the stream may start just after the first.
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		for ctx.Err() == nil {
			_, _ = get(base + "/across-instances") //nolint:contextcheck // every request has its own timeout.
			timer := time.NewTimer(300 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	})
	waitLine(t, live, "request GET /across-instances", 30*time.Second)
	cancel()
}

// TestAppLogsLimits: since and tail are validated, and logs of an app
// with no instance are a clear 404.
func TestAppLogsLimits(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": "web"}), 201, "create")
	expectStatus(t, e.as(alice, http.MethodGet, appURL(alice.personal, "web")+"/logs?tail=99999", nil), 400, "tail")
	expectStatus(t, e.as(alice, http.MethodGet, appURL(alice.personal, "web")+"/logs?since=yesterday", nil), 400, "since")
	expectStatus(t, e.as(alice, http.MethodGet, appURL(alice.personal, "web")+"/logs", nil), 404, "no instance")
	for range 30 {
		e.as(alice, http.MethodGet, appURL(alice.personal, "web")+"/logs", nil)
	}
	expectStatus(t, e.as(alice, http.MethodGet, appURL(alice.personal, "web")+"/logs", nil), 429, "rate limit")
}

// placementFixture creates n apps with a recorded deployment each, for
// placement tests without a running agent.
func placementFixture(t *testing.T, e *env, n int) []scheduler.Placement {
	t.Helper()
	alice := e.adminAlice()
	var out []scheduler.Placement
	for i := range n {
		slug := "app" + itoa(int32(i))
		expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": slug}), 201, "create")
		var p scheduler.Placement
		err := e.db.QueryRow(context.Background(), `
			WITH a AS (SELECT a.id, a.workspace_id FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE w.slug = $1 AND a.slug = $2)
			INSERT INTO deployments (app_id, number, status, source_key, source_sha256, source_size, upload_expires_at)
			SELECT a.id, 1, 'pending', 'k', decode(repeat('00', 32), 'hex'), 1, now() FROM a
			RETURNING app_id, id, (SELECT workspace_id FROM a)`, alice.personal, slug).Scan(&p.AppID, &p.DeploymentID, &p.WorkspaceID)
		if err != nil {
			t.Fatal(err)
		}
		p.MemoryMB, p.Millicores = 600, 100
		out = append(out, p)
	}
	return out
}

// addNode records a ready node with memMB of memory (before the reserve).
func addNode(t *testing.T, e *env, name string, memMB int64) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := e.db.QueryRow(context.Background(), `
		INSERT INTO nodes (name, status, advertise_address, memory_total_bytes, cpu_count)
		VALUES ($1, 'ready', '10.0.0.1', $2, 4) RETURNING id`, name, memMB<<20).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestPlacementRaceGivesTheLastCapacityToOne: two placements racing for a
// node with room for one: exactly one succeeds, every time.
func TestPlacementRaceGivesTheLastCapacityToOne(t *testing.T) {
	e := startEnv(t)
	ps := placementFixture(t, e, 2)
	addNode(t, e, "small", 512+1000) // 1000 MB for apps: one 600 MB instance
	st := store.NewStore(e.db)
	cfg := scheduler.Config{ReservedMemoryMB: 512, ReservedMillicores: 0}
	for round := range 10 {
		e.exec("DELETE FROM app_instances")
		results := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Go(func() {
				<-start
				results[i] = st.InTx(context.Background(), func(q *store.Queries) error {
					_, err := scheduler.Place(context.Background(), q, &cfg, &ps[i])
					return err
				})
			})
		}
		close(start)
		wg.Wait()
		placed, refused := 0, 0
		for _, err := range results {
			switch {
			case err == nil:
				placed++
			case errors.Is(err, scheduler.ErrNoCapacity):
				refused++
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if placed != 1 || refused != 1 || e.count("SELECT count(*) FROM app_instances") != 1 {
			t.Fatalf("round %d: placed %d, refused %d", round, placed, refused)
		}
	}
}

// TestPlacementSkipsDrainingNodesAndPicksTheBestFit: the node left with
// the least room wins unless it is draining; with every node draining
// nothing is placed.
func TestPlacementSkipsDrainingNodesAndPicksTheBestFit(t *testing.T) {
	e := startEnv(t)
	ps := placementFixture(t, e, 1)
	tight := addNode(t, e, "tight", 512+700)
	addNode(t, e, "roomy", 512+8000)
	st := store.NewStore(e.db)
	cfg := scheduler.Config{ReservedMemoryMB: 512}
	place := func() (store.AppInstance, error) {
		var inst store.AppInstance
		err := st.InTx(context.Background(), func(q *store.Queries) error {
			res, err := scheduler.Place(context.Background(), q, &cfg, &ps[0])
			inst = res.Instance
			return err
		})
		return inst, err
	}
	inst, err := place()
	if err != nil || inst.NodeName != "tight" {
		t.Fatalf("best fit: %v %+v", err, inst)
	}
	e.exec("DELETE FROM app_instances")
	e.exec("UPDATE nodes SET draining = true WHERE id = $1", tight)
	if inst, err = place(); err != nil || inst.NodeName != "roomy" {
		t.Fatalf("draining node chosen: %v %+v", err, inst)
	}
	e.exec("DELETE FROM app_instances")
	e.exec("UPDATE nodes SET draining = true")
	if _, err = place(); !errors.Is(err, scheduler.ErrNoCapacity) {
		t.Fatalf("all nodes draining: %v", err)
	}
}

// TestInsufficientCapacityFailsCleanly: a release that fits nowhere fails
// with a clear reason; the live version keeps running. The memory quota
// is enforced the same way.
func TestInsufficientCapacityFailsCleanly(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	n1 := r.release(r.ws, "web")
	r.waitLive(r.alice, r.ws, "web", n1)
	base := r.appBase(r.alice, r.ws, "web")
	// The node now has room for 100 MB of apps; 64 MB are taken.
	r.exec("UPDATE nodes SET memory_total_bytes = $1", int64(512+100)<<20)
	n2 := r.release(r.ws, "web")
	d := r.waitStatus(r.alice, r.ws, "web", n2, time.Minute, "failed", "live")
	if d.Status != "failed" || !strings.Contains(d.FailureReason, "insufficient capacity") {
		t.Fatalf("deployment %+v", d)
	}
	if code, body := get(base + "/"); code != http.StatusOK || !strings.Contains(body, "deployment 1") {
		t.Fatalf("live version: %d %q", code, body)
	}

	r.exec("UPDATE nodes SET memory_total_bytes = $1", int64(16)<<30)
	expectStatus(t, r.as(r.alice, http.MethodPut, "/api/v1/admin/workspaces/"+r.ws+"/quota",
		map[string]any{"max_apps": 20, "max_concurrent_builds": 2, "max_memory_mb": 100}), 200, "set quota")
	r.newRuntimeApp(r.alice, r.ws, "second", nil)
	n := r.release(r.ws, "second")
	d = r.waitStatus(r.alice, r.ws, "second", n, time.Minute, "failed", "live")
	if d.Status != "failed" || !strings.Contains(d.FailureReason, "memory quota is 100 MB") {
		t.Fatalf("quota: %+v", d)
	}
}

// TestStopAndStart: a stopped app runs nothing and releases nothing; a
// deployment made meanwhile is released when it starts.
func TestStopAndStart(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	n1 := r.release(r.ws, "web")
	r.waitLive(r.alice, r.ws, "web", n1)
	base := r.appBase(r.alice, r.ws, "web")
	expectStatus(t, r.as(r.alice, http.MethodPost, appURL(r.ws, "web")+"/stop", nil), 200, "stop")
	eventually(t, 30*time.Second, "the app to stop", func() bool {
		code, _ := get(base + "/healthz")
		return code != http.StatusOK && r.app(r.alice, r.ws, "web").Health == "stopped"
	})
	n2 := r.release(r.ws, "web")
	if d := r.waitStatus(r.alice, r.ws, "web", n2, time.Minute, "built", "live"); d.Status != "built" {
		t.Fatalf("a stopped app released #%d: %s", n2, d.Status)
	}
	expectStatus(t, r.as(r.alice, http.MethodPost, appURL(r.ws, "web")+"/start", nil), 200, "start")
	r.waitLive(r.alice, r.ws, "web", n2)
	if code, body := get(r.appBase(r.alice, r.ws, "web") + "/"); code != http.StatusOK || !strings.Contains(body, "deployment 2") {
		t.Fatalf("after start: %d %q", code, body)
	}
}

// TestRuntimeEndpointsAreTenantScoped: a non-member gets 404 from every
// new endpoint of another workspace's app, never 403.
func TestRuntimeEndpointsAreTenantScoped(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	bob := e.newUser("bob@nook.test")
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": "web"}), 201, "create")
	expectStatus(t, e.as(alice, http.MethodPut, appURL(alice.personal, "web")+"/env", map[string]any{"vars": map[string]string{"A": "1"}}), 200, "set env")
	app := appURL(alice.personal, "web")
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, app, nil},
		{http.MethodPatch, app, map[string]any{"port": 9000}},
		{http.MethodPost, app + "/stop", nil},
		{http.MethodPost, app + "/start", nil},
		{http.MethodPost, app + "/rollback", map[string]any{}},
		{http.MethodGet, app + "/logs", nil},
		{http.MethodGet, app + "/env", nil},
		{http.MethodPut, app + "/env", map[string]any{"vars": map[string]string{"A": "2"}}},
		{http.MethodDelete, app + "/env/A", nil},
	} {
		expectStatus(t, e.as(bob, c.method, c.path, c.body), http.StatusNotFound, "bob "+c.method+" "+c.path)
	}
	expectStatus(t, e.as(alice, http.MethodPatch, app, map[string]any{"startup_timeout_seconds": 100000}), 400, "startup above the maximum")
	expectStatus(t, e.as(alice, http.MethodPatch, app, map[string]any{"port": 9000, "read_only_rootfs": true}), 200, "update")
	if !strings.Contains(e.as(alice, http.MethodGet, app, nil).body, `"read_only_rootfs":true`) {
		t.Fatal("update not applied")
	}
}

// TestMasterKeyChecksAndRotation: a server refuses to start with the wrong
// key or without a version stored values need; rotation re-encrypts every
// value, after which the old key can be dropped.
func TestMasterKeyChecksAndRotation(t *testing.T) {
	e := startEnv(t)
	alice := e.adminAlice()
	expectStatus(t, e.as(alice, http.MethodPost, appsURL(alice.personal), map[string]any{"slug": "web"}), 201, "create")
	expectStatus(t, e.as(alice, http.MethodPut, appURL(alice.personal, "web")+"/env",
		map[string]any{"vars": map[string]string{"TOKEN": "rotate-me"}, "secret": true}), 200, "set secret")
	expectStatus(t, e.as(alice, http.MethodPut, appURL(alice.personal, "web")+"/env",
		map[string]any{"vars": map[string]string{"PLAIN": "visible"}}), 200, "set plain")
	e.exec("INSERT INTO env_snapshots (id, app_id) SELECT $1, app_id FROM app_env LIMIT 1", uuid.NewV7())
	e.exec("INSERT INTO env_snapshot_vars SELECT s.id, v.key, v.value, v.key_version, v.is_secret FROM env_snapshots s, app_env v")

	start := func(key string) error {
		environ := baseEnviron(e.dbURL)
		environ["NOOK_SECRETS_KEY"] = key
		cfg, err := config.Load[Config](environ)
		if err != nil {
			return err
		}
		srv, err := New(context.Background(), &cfg, quietLogger)
		if err == nil {
			srv.Close()
		}
		return err
	}
	other, _ := secrets.NewKeyLine(1)
	if err := start(other); err == nil || !strings.Contains(err.Error(), "key version 1 is not the key") {
		t.Fatalf("wrong key: %v", err)
	}
	onlyV2, _ := secrets.NewKeyLine(2)
	if err := start(onlyV2); err == nil || !strings.Contains(err.Error(), "which the keyring lacks") {
		t.Fatalf("missing version: %v", err)
	}

	ring, err := secrets.ParseKeyring(testSecretsKey + "\n" + onlyV2)
	if err != nil {
		t.Fatal(err)
	}
	n, err := secrets.Rotate(context.Background(), store.NewStore(e.db), ring)
	if err != nil || n != 4 {
		t.Fatalf("rotate: %d %v", n, err)
	}
	if left := e.count("SELECT count(*) FROM app_env WHERE key_version <> 2") + e.count("SELECT count(*) FROM env_snapshot_vars WHERE key_version <> 2"); left != 0 {
		t.Fatalf("%d values still on the old key", left)
	}
	if n, err := secrets.Rotate(context.Background(), store.NewStore(e.db), ring); err != nil || n != 0 {
		t.Fatalf("second rotation: %d %v", n, err)
	}
	// The old key can go: a server with only version 2 starts and reads.
	e.primary.stop()
	e.base = e.startInstance(map[string]string{"NOOK_SECRETS_KEY": onlyV2}).base
	res := e.bearer(alice.token, http.MethodGet, appURL(alice.personal, "web")+"/env", nil)
	if !strings.Contains(res.body, `"value":"visible"`) || strings.Contains(res.body, "rotate-me") {
		t.Fatalf("env after rotation: %s", res.body)
	}
	if !strings.Contains(strings.Join(e.auditActions(), ","), "secrets.rotate_key") {
		t.Fatal("rotation not audited")
	}
}

// TestStoppingOnARemovedNodeCompletes: an instance whose node was removed
// can never confirm a stop; stopping the app records it as stopped, so
// it holds no reservation and a deleted app can be purged.
func TestStoppingOnARemovedNodeCompletes(t *testing.T) {
	r := startRuntimeEnv(t, nil)
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	expectStatus(t, r.as(r.alice, http.MethodDelete, "/api/v1/nodes/builder-1", nil), http.StatusNoContent, "remove node")
	expectStatus(t, r.as(r.alice, http.MethodPost, appURL(r.ws, "web")+"/stop", nil), http.StatusOK, "stop")
	eventually(t, 30*time.Second, "the instance to be stopped", func() bool {
		return r.count("SELECT count(*) FROM app_instances WHERE state IN ('starting', 'healthy', 'unhealthy', 'stopping')") == 0
	})
}
