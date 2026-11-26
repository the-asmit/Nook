//go:build integration

package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWakePrefersThePreviousNode: a sleeping app resumes on its node (the
// same instance and container) when the node has room; when it is full,
// it wakes on another node and its kept container on the full node goes.
func TestWakePrefersThePreviousNode(t *testing.T) {
	r := startRuntimeEnv(t, map[string]string{"NOOK_QUOTA_MAX_MEMORY_MB": "1048576", "NOOK_ROLLOUT_IDLE_INTERVAL": noIdlePass["NOOK_ROLLOUT_IDLE_INTERVAL"]})
	r.joinBuilder("node-b", r.primary.grpc)
	r.newRuntimeApp(r.alice, r.ws, "web", map[string]any{"sleep_after": "1m"})
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	_, web := r.appIDs(r.ws, "web")
	first := r.newestInstance(web)
	if first.Node != "builder-1" {
		t.Fatalf("placed on %s, want builder-1 (best fit, then name)", first.Node)
	}
	sleep := func() {
		t.Helper()
		setActivity(t, web, time.Now().Add(-time.Hour))
		if n := r.sleepIdle(time.Now().Add(2 * time.Minute)); n != 1 {
			t.Fatalf("%d apps slept, want 1", n)
		}
	}
	wake := func() instanceRow {
		t.Helper()
		expectStatus(t, r.as(r.alice, http.MethodPost, appURL(r.ws, "web")+"/wake", nil), http.StatusAccepted, "wake")
		eventually(t, time.Minute, "the app to wake", func() bool { return r.app(r.alice, r.ws, "web").Health == "running" })
		return r.newestInstance(web)
	}

	// Woken right after falling asleep: the start reaches the agent while
	// it may still be stopping the container, and must run after the stop.
	sleep()
	if got := wake(); got.ID != first.ID || got.Node != "builder-1" || got.ContainerID != first.ContainerID || got.Cause != "wake" {
		t.Fatalf("woke as %+v; want instance %s resumed on builder-1 with its container", got, first.ID)
	}

	sleep()
	r.fill("builder-1", 10) // no room for the app's 64 MB
	moved := wake()
	if moved.ID == first.ID || moved.Node != "node-b" {
		t.Fatalf("woke as %+v; want a new instance on node-b", moved)
	}
	if old := r.instance(first.ID); old.State != "stopped" {
		t.Fatalf("the sleeping instance on the full node is %s, want stopped", old.State)
	}
	eventually(t, time.Minute, "the kept container on the full node to be removed", func() bool { return containerState(t, first.ContainerID) == "" })
}

// TestNodeDeathMovesAppsAndFencesTheOldOne: when the node running an app
// dies, the app is healthy on another node within the failover bound and
// the gateway routes there; the old container, still running while its
// node is cut off, never receives traffic, and is removed when the node
// comes back.
func TestNodeDeathMovesAppsAndFencesTheOldOne(t *testing.T) {
	r := startRuntimeEnv(t, map[string]string{"NOOK_ROLLOUT_RELOCATE_INTERVAL": "200ms"})
	r.joinBuilder("node-b", r.primary.grpc)
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	r.publicApp("web")
	r.startGateway(nil)
	_, web := r.appIDs(r.ws, "web")
	old := r.newestInstance(web)
	if old.Node != "builder-1" {
		t.Fatalf("placed on %s, want builder-1", old.Node)
	}
	url := appOrigin(r.ws, "web") + "/"
	if res := newVisitor(t).get(url); res.status != http.StatusOK {
		t.Fatalf("before: %d", res.status)
	}

	// The node's agent dies; its container keeps running (as after a
	// network partition), but nothing on the control plane hears from it.
	r.agent.stop()
	if ok, _ := r.agent.exited(10 * time.Second); !ok {
		t.Fatal("the agent did not stop")
	}
	killed := time.Now()
	var moved instanceRow
	eventually(t, 2*time.Minute, "the app to run on node-b", func() bool {
		moved = r.newestInstance(web)
		return moved.Node == "node-b" && moved.State == "healthy"
	})
	sinceKill := time.Since(killed)
	if moved.Cause != "failover" || moved.CauseAt == nil || moved.LastHealthy == nil {
		t.Fatalf("replacement %+v", moved)
	}
	took := moved.LastHealthy.Sub(*moved.CauseAt)
	// Bound: dead threshold (4 s here) + relocation interval + placement +
	// start and health check of the test app.
	if sinceKill > 4*time.Second+30*time.Second || took > 30*time.Second {
		t.Fatalf("failover took %s after the node died (%s after the kill)", took, sinceKill)
	}
	t.Logf("failover: node declared dead -> healthy elsewhere in %s (%s after the agent died)", took.Round(time.Millisecond), sinceKill.Round(time.Millisecond))
	if v := metricValue(t, r.base+"/metrics", "nook_app_failover_seconds_count"); v != 1 {
		t.Fatalf("nook_app_failover_seconds_count = %v", v)
	}

	// Fencing: the old container still runs, but the route is the new one.
	if state := containerState(t, old.ContainerID); state != "running" {
		t.Fatalf("the old container is %q; the test wants it running to show it gets no traffic", state)
	}
	if got := r.instance(old.ID); got.State != "stopping" {
		t.Fatalf("the old instance is %s, want stopping (failed over)", got.State)
	}
	newPort := strconv.Itoa(int(*r.app(r.alice, r.ws, "web").Instance.HostPort))
	eventually(t, 10*time.Second, "the gateway to route to node-b", func() bool {
		route := r.internal(testGatewaySecret, "/internal/v1/routes/"+web.String())
		return strings.Contains(route.body, `"upstream":"127.0.0.1:`+newPort+`"`)
	})
	for range 20 {
		if res := newVisitor(t).get(url); res.status != http.StatusOK {
			t.Fatalf("after failover: %d", res.status)
		}
	}

	// The node comes back: reconciliation removes the stale container and
	// the route stays where it is.
	cfg := agentConfigWith(t, r.agentState, r.agentOverrides)
	runConfiguredAgent(t, &cfg, quietLogger)
	eventually(t, time.Minute, "the stale container to be removed", func() bool {
		return containerState(t, old.ContainerID) == "" && r.instance(old.ID).State == "stopped"
	})
	if route := r.internal(testGatewaySecret, "/internal/v1/routes/"+web.String()); !strings.Contains(route.body, `"upstream":"127.0.0.1:`+newPort+`"`) {
		t.Fatalf("route after the node returned: %s", route.body)
	}
}

// TestFailedOverInstanceStopsWhenItsNodeReturnsWithoutReconnecting: a node
// declared dead while its agent stays connected (late heartbeats) comes
// back by heartbeats alone, so reconnection reconciliation never runs; the
// leader still has the failed-over container removed, and the app runs
// again.
func TestFailedOverInstanceStopsWhenItsNodeReturnsWithoutReconnecting(t *testing.T) {
	r := startRuntimeEnv(t, map[string]string{"NOOK_ROLLOUT_RELOCATE_INTERVAL": "200ms"})
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	_, web := r.appIDs(r.ws, "web")
	old := r.newestInstance(web)

	// What the failure detector does when heartbeats are late; the next
	// heartbeat makes the node ready again (the agent never disconnects).
	eventually(t, 30*time.Second, "the instance to be failed over", func() bool {
		r.exec(`UPDATE nodes SET status = 'dead' WHERE name = $1 AND status = 'ready'`, old.Node)
		return r.instance(old.ID).State == "stopping"
	})
	eventually(t, time.Minute, "the failed-over container to go and the app to run again", func() bool {
		return containerState(t, old.ContainerID) == "" && r.instance(old.ID).State == "stopped" &&
			r.app(r.alice, r.ws, "web").Health == "running"
	})
	if n := r.newestInstance(web); n.ID == old.ID || n.Cause != "failover" || n.State != "healthy" {
		t.Fatalf("after the node returned: %+v", n)
	}
}

// TestDrainMovesAppsWithoutFailedRequests: draining a node moves its app
// to another node while requests keep flowing through the gateway; none
// fails, and the drain completes with nothing left on the node.
func TestDrainMovesAppsWithoutFailedRequests(t *testing.T) {
	r := startRuntimeEnv(t, map[string]string{"NOOK_ROLLOUT_RELOCATE_INTERVAL": "200ms"})
	r.joinBuilder("node-b", r.primary.grpc)
	r.newRuntimeApp(r.alice, r.ws, "web", nil)
	r.waitLive(r.alice, r.ws, "web", r.release(r.ws, "web"))
	r.publicApp("web")
	// One client sends requests back to back: above the per-IP limit.
	r.startGateway(map[string]string{"NOOK_GATEWAY_RATE_PER_IP": "100000", "NOOK_GATEWAY_BURST_PER_IP": "100000"})
	_, web := r.appIDs(r.ws, "web")
	if n := r.newestInstance(web).Node; n != "builder-1" {
		t.Fatalf("placed on %s, want builder-1", n)
	}

	url := appOrigin(r.ws, "web") + "/"
	var ok, failed atomic.Int64
	var mu sync.Mutex
	var failures []string
	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	visitor := newVisitor(t)
	wg.Go(func() {
		for ctx.Err() == nil {
			status, body := visitorGet(ctx, visitor, url)
			if ctx.Err() != nil {
				return // canceled by the test at the end, not a failure
			}
			if status == http.StatusOK {
				ok.Add(1)
			} else {
				failed.Add(1)
				mu.Lock()
				failures = append(failures, strconv.Itoa(status)+" "+body)
				mu.Unlock()
			}
		}
	})
	eventually(t, 10*time.Second, "requests flowing", func() bool { return ok.Load() >= 10 })

	start := time.Now()
	expectStatus(t, r.as(r.alice, http.MethodPost, "/api/v1/nodes/builder-1/drain", nil), http.StatusOK, "drain")
	eventually(t, 2*time.Minute, "the drain to complete", func() bool {
		var n struct {
			ActiveInstances int64 `json:"active_instances"`
		}
		r.as(r.alice, http.MethodGet, "/api/v1/nodes/builder-1", nil).json(t, &n)
		return n.ActiveInstances == 0
	})
	drained := time.Since(start)
	served := ok.Load()
	eventually(t, 10*time.Second, "more requests after the drain", func() bool { return ok.Load() >= served+20 })
	stop()
	wg.Wait()
	if failed.Load() != 0 {
		t.Fatalf("%d of %d requests failed during the drain: %v", failed.Load(), ok.Load()+failed.Load(), failures)
	}
	if moved := r.newestInstance(web); moved.Node != "node-b" || moved.State != "healthy" || moved.Cause != "drain" {
		t.Fatalf("after the drain: %+v", moved)
	}
	if v := metricValue(t, r.base+"/metrics", "nook_app_drain_move_seconds_count"); v != 1 {
		t.Fatalf("nook_app_drain_move_seconds_count = %v", v)
	}
	t.Logf("drain: %d requests, 0 failed; node empty after %s", ok.Load(), drained.Round(time.Millisecond))
}

// visitorGet fetches url without failing the test (for background loops).
func visitorGet(ctx context.Context, v *appVisitor, url string) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, err.Error()
	}
	resp, err := v.c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	var b strings.Builder
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	b.Write(buf[:n])
	return resp.StatusCode, b.String()
}
