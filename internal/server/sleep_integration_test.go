//go:build integration

package server

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/testinfra"
)

// TestIdleAppsSleepAndOneWakeServesEveryone: an app sleeps exactly when
// its sleep_after has passed since its last request (the leader's clock is
// injected), releasing its reservation and keeping its stopped container;
// an app with sleep_after = never does not. Then 100 concurrent requests
// through two gateways wake it with exactly one container start (its own
// container, on its own node) and all get the app's answer.
func TestIdleAppsSleepAndOneWakeServesEveryone(t *testing.T) {
	r := startRuntimeEnv(t, noIdlePass)
	r.newRuntimeApp(r.alice, r.ws, "sleepy", map[string]any{"sleep_after": "1m"})
	r.newRuntimeApp(r.alice, r.ws, "awake", map[string]any{"sleep_after": "never"})
	r.waitLive(r.alice, r.ws, "sleepy", r.release(r.ws, "sleepy"))
	r.waitLive(r.alice, r.ws, "awake", r.release(r.ws, "awake"))
	r.publicApp("sleepy")
	_, sleepy := r.appIDs(r.ws, "sleepy")
	_, awake := r.appIDs(r.ws, "awake")
	before := r.newestInstance(sleepy)

	// Last request: a moment after the instance became healthy (activity
	// is kept in whole milliseconds).
	last := before.LastHealthy.Add(5 * time.Second).Truncate(time.Millisecond)
	setActivity(t, sleepy, last)
	setActivity(t, awake, last)
	if n := r.sleepIdle(last.Add(time.Minute - time.Millisecond)); n != 0 {
		t.Fatalf("%d apps slept before their sleep_after", n)
	}
	if n := r.sleepIdle(last.Add(time.Minute)); n != 1 {
		t.Fatalf("%d apps slept at their sleep_after, want 1", n)
	}
	if n := r.sleepIdle(last.Add(1000 * time.Hour)); n != 0 {
		t.Fatalf("an app with sleep_after = never slept")
	}
	if a := r.app(r.alice, r.ws, "awake"); a.Health != "running" {
		t.Fatalf("the never-sleeping app is %s", a.Health)
	}
	var info struct {
		Health        string     `json:"health"`
		SleepingSince *time.Time `json:"sleeping_since"`
		SleepReason   string     `json:"sleep_reason"`
		LastRequestAt *time.Time `json:"last_request_at"`
	}
	r.as(r.alice, http.MethodGet, appURL(r.ws, "sleepy"), nil).json(t, &info)
	if info.Health != "sleeping" || info.SleepingSince == nil || info.SleepReason != "idle" || info.LastRequestAt == nil || !info.LastRequestAt.Equal(last) {
		t.Fatalf("sleeping app: %+v", info)
	}
	// Its reservation is released; its container is stopped but kept.
	if n := r.count(`SELECT count(*) FROM app_instances WHERE app_id = $1 AND state IN ('starting', 'healthy', 'unhealthy', 'stopping')`, sleepy); n != 0 {
		t.Fatalf("%d instances of the sleeping app still reserve resources", n)
	}
	eventually(t, 30*time.Second, "the container to stop", func() bool { return containerState(t, before.ContainerID) == "exited" })
	stoppedAt := containerFinishedAt(t, before.ContainerID)
	if v := metricValue(t, r.base+"/metrics", "nook_apps_sleeping"); v != 1 {
		t.Fatalf("nook_apps_sleeping = %v", v)
	}
	if v := metricValue(t, r.base+"/metrics", "nook_apps_sleeping_released_memory_bytes"); v != 64<<20 {
		t.Fatalf("released memory = %v", v)
	}

	// Two gateways, 50 concurrent requests each.
	g1 := r.startGateway(nil)
	port2, err := testinfra.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	g2 := r.startGateway(map[string]string{"NOOK_GATEWAY_HTTP_ADDR": "127.0.0.1:" + strconv.Itoa(port2)})
	host := "sleepy--" + r.ws + ".apps.localhost"
	const n = 100
	results := make([]response, n)
	var wg sync.WaitGroup
	for i := range n {
		addr := g1.Addrs()[0].String()
		if i%2 == 1 {
			addr = g2.Addrs()[0].String()
		}
		wg.Go(func() {
			req := newRequest(t, http.MethodGet, "http://"+addr+"/", http.NoBody)
			req.Host = host
			results[i] = send(t, &http.Client{Timeout: time.Minute}, req)
		})
	}
	wg.Wait()
	for i, res := range results {
		if res.status != http.StatusOK || !strings.Contains(res.body, "testapp deployment 1") {
			t.Fatalf("request %d: %d %.200s", i, res.status, res.body)
		}
	}
	if starts := containerStarts(t, sleepy, stoppedAt); starts != 1 {
		t.Fatalf("%d container starts for %d concurrent requests, want exactly 1", starts, n)
	}
	after := r.newestInstance(sleepy)
	if after.ID != before.ID || after.ContainerID != before.ContainerID || after.State != "healthy" || after.Cause != "wake" {
		t.Fatalf("woke as %+v; want the same instance and container resumed (was %+v)", after, before)
	}
	if a := r.app(r.alice, r.ws, "sleepy"); a.Health != "running" {
		t.Fatalf("after waking: %s", a.Health)
	}
	// Metrics: one wake on the control plane, one per gateway.
	if v := metricValue(t, r.base+"/metrics", "nook_app_wake_seconds_count"); v != 1 {
		t.Fatalf("nook_app_wake_seconds_count = %v", v)
	}
	for _, g := range []string{g1.OpsAddr().String(), g2.OpsAddr().String()} {
		if v := metricValue(t, "http://"+g+"/metrics", "nook_gateway_wake_seconds_count"); v != 1 {
			t.Fatalf("gateway %s: nook_gateway_wake_seconds_count = %v", g, v)
		}
	}
	if v := metricValue(t, r.base+"/metrics", "nook_apps_sleeping"); v != 0 {
		t.Fatalf("nook_apps_sleeping after waking = %v", v)
	}
	if v := metricValue(t, r.base+"/metrics", `nook_app_sleeps_total{reason="idle"}`); v != 1 {
		t.Fatalf("sleeps = %v", v)
	}
}

// TestEvictionSleepsLeastRecentlyUsedApps: when a release fits nowhere,
// the least recently used idle apps that may sleep are put to sleep on one
// node until it fits; apps with sleep_after = never are never chosen; a
// release that eviction cannot make room for fails cleanly and evicts
// nothing.
func TestEvictionSleepsLeastRecentlyUsedApps(t *testing.T) {
	r := startRuntimeEnv(t, map[string]string{"NOOK_QUOTA_MAX_MEMORY_MB": "1048576", "NOOK_ROLLOUT_IDLE_INTERVAL": noIdlePass["NOOK_ROLLOUT_IDLE_INTERVAL"]})
	for _, app := range []struct{ slug, sleepAfter string }{{"older", "1m"}, {"newer", "1m"}, {"pinned", "never"}} {
		r.newRuntimeApp(r.alice, r.ws, app.slug, map[string]any{"sleep_after": app.sleepAfter})
		r.waitLive(r.alice, r.ws, app.slug, r.release(r.ws, app.slug))
	}
	ids := map[string]uuid.UUID{}
	for _, slug := range []string{"older", "newer", "pinned"} {
		_, ids[slug] = r.appIDs(r.ws, slug)
	}
	// Idle for 10 minutes, 5 minutes and an hour (the never-sleeping app is
	// the least recently used of all).
	now := time.Now()
	for slug, idle := range map[string]time.Duration{"older": 10 * time.Minute, "newer": 5 * time.Minute, "pinned": time.Hour} {
		setActivity(t, ids[slug], now.Add(-idle))
		r.exec("UPDATE app_instances SET last_healthy_at = $2 WHERE app_id = $1", ids[slug], now.Add(-idle))
	}
	node := r.newestInstance(ids["older"]).Node
	r.fill(node, 100) // 100 MB left; each test app reserves 64 MB

	// 128 MB: one eviction makes room (100 + 64), the least recently used
	// app that may sleep.
	r.newRuntimeApp(r.alice, r.ws, "big", map[string]any{"memory_mb": 128})
	n := r.release(r.ws, "big")
	r.waitLive(r.alice, r.ws, "big", n)
	if a := r.app(r.alice, r.ws, "older"); a.Health != "sleeping" {
		t.Fatalf("the least recently used app is %s, want sleeping", a.Health)
	}
	for _, slug := range []string{"newer", "pinned"} {
		if a := r.app(r.alice, r.ws, slug); a.Health != "running" {
			t.Fatalf("%s is %s, want running", slug, a.Health)
		}
	}
	var reason string
	if err := r.db.QueryRow(context.Background(), "SELECT sleep_reason FROM apps WHERE id = $1", ids["older"]).Scan(&reason); err != nil || reason != "evicted" {
		t.Fatalf("sleep reason %q, %v", reason, err)
	}
	if !slices.Contains(r.auditActions(), "app.evict") {
		t.Fatal("the eviction was not audited")
	}
	if log := r.buildLog(r.alice, r.ws, "big", n); !strings.Contains(log, "put idle app older to sleep on node "+node+" to make room") {
		t.Fatalf("the release log does not mention the eviction:\n%s", log)
	}
	if v := metricValue(t, r.base+"/metrics", `nook_app_sleeps_total{reason="evicted"}`); v != 1 {
		t.Fatalf("evictions = %v", v)
	}

	// 200 MB: 36 MB are free and only "newer" (64 MB) may still sleep: no
	// eviction can make room, so the release fails and nothing sleeps.
	r.newRuntimeApp(r.alice, r.ws, "huge", map[string]any{"memory_mb": 200})
	d := r.waitStatus(r.alice, r.ws, "huge", r.release(r.ws, "huge"), 3*time.Minute, "live", "failed")
	if d.Status != "failed" || !strings.Contains(d.FailureReason, "insufficient capacity") {
		t.Fatalf("huge: %s %q", d.Status, d.FailureReason)
	}
	if a := r.app(r.alice, r.ws, "newer"); a.Health != "running" {
		t.Fatalf("a failed eviction put newer to sleep (%s)", a.Health)
	}
	if v := metricValue(t, r.base+"/metrics", `nook_app_sleeps_total{reason="evicted"}`); v != 1 {
		t.Fatalf("evictions after the failed release = %v", v)
	}
}
