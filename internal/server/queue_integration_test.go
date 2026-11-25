//go:build integration

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/the-asmit/nook/internal/store"
)

// startQueueOnly is a control plane without any build node: deployments
// stay queued.
func startQueueOnly(t *testing.T, overrides map[string]string) *buildEnv {
	t.Helper()
	e := startEnvWith(t, overrides)
	alice := e.adminAlice()
	return &buildEnv{env: e, alice: alice, ws: alice.personal}
}

func TestCancelQueuedDeployment(t *testing.T) {
	b := startQueueOnly(t, nil)
	b.createApp(b.alice, b.ws, "web")
	n := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile("queued")))
	b.waitStatus(b.alice, b.ws, "web", n, 10*time.Second, "queued")
	r := b.as(b.alice, http.MethodPost, appURL(b.ws, "web")+"/deployments/1/cancel", nil)
	var d deploymentResp
	r.json(t, &d)
	if r.status != http.StatusOK || d.Status != statusCancelled {
		t.Fatalf("cancel: %d %s", r.status, r.body)
	}
	if r := b.as(b.alice, http.MethodPost, appURL(b.ws, "web")+"/deployments/1/cancel", nil); r.status != http.StatusConflict {
		t.Fatalf("canceling twice: %d", r.status)
	}
	if b.count("SELECT count(*) FROM builds") != 0 {
		t.Fatal("a canceled queued deployment was built")
	}
}

func TestNewerDeploySupersedesQueued(t *testing.T) {
	b := startQueueOnly(t, nil)
	b.createApp(b.alice, b.ws, "web")
	first := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile("one")))
	second := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile("two")))
	d1 := b.deployment(b.alice, b.ws, "web", first)
	if d1.Status != statusCancelled || d1.FailureReason != "superseded by deployment #2" {
		t.Fatalf("first: %+v", d1)
	}
	if d2 := b.deployment(b.alice, b.ws, "web", second); d2.Status != "queued" {
		t.Fatalf("second: %+v", d2)
	}
	// An older deploy confirmed after a newer one is queued loses at once.
	data, c := b.startDeploy(b.alice, b.ws, "web", project(t, helloDockerfile("three")))
	data4, c4 := b.startDeploy(b.alice, b.ws, "web", project(t, helloDockerfile("four")))
	if upload(t, &c, data) != http.StatusOK || upload(t, &c4, data4) != http.StatusOK {
		t.Fatal("upload")
	}
	expectStatus(t, b.as(b.alice, http.MethodPost, appURL(b.ws, "web")+"/deployments/4/upload-complete", nil), 200, "confirm #4")
	expectStatus(t, b.as(b.alice, http.MethodPost, appURL(b.ws, "web")+"/deployments/3/upload-complete", nil), 200, "confirm #3")
	if d := b.deployment(b.alice, b.ws, "web", 3); d.Status != statusCancelled {
		t.Fatalf("older deploy confirmed late: %+v", d)
	}
	if d := b.deployment(b.alice, b.ws, "web", 2); d.Status != statusCancelled {
		t.Fatalf("#2 not superseded by #4: %+v", d)
	}
	if d := b.deployment(b.alice, b.ws, "web", 4); d.Status != "queued" {
		t.Fatalf("#4: %+v", d)
	}
}

func TestNoBuildCapacityFails(t *testing.T) {
	b := startQueueOnly(t, map[string]string{"NOOK_BUILD_QUEUE_TIMEOUT": "5s"})
	b.createApp(b.alice, b.ws, "web")
	n := b.deploy(b.alice, b.ws, "web", project(t, helloDockerfile("nobody")))
	d := b.waitStatus(b.alice, b.ws, "web", n, 30*time.Second, "failed")
	if !strings.Contains(d.FailureReason, "no build capacity") {
		t.Fatalf("reason %q", d.FailureReason)
	}
}

func TestCancelRunningBuild(t *testing.T) {
	b := startBuildEnv(t, nil)
	b.createApp(b.alice, b.ws, "slow")
	n := b.deploy(b.alice, b.ws, "slow", project(t, slowDockerfile("running", 300)))
	b.waitStatus(b.alice, b.ws, "slow", n, 2*time.Minute, "building")
	eventually(t, 2*time.Minute, "the build to run", func() bool { return strings.Contains(b.buildLog(b.alice, b.ws, "slow", n), "running") })

	r := b.as(b.alice, http.MethodPost, appURL(b.ws, "slow")+"/deployments/1/cancel", nil)
	var d deploymentResp
	r.json(t, &d)
	if r.status != http.StatusOK || !d.CancelRequested {
		t.Fatalf("cancel: %d %s", r.status, r.body)
	}
	d = b.waitStatus(b.alice, b.ws, "slow", n, time.Minute, statusCancelled)
	if len(d.Builds) != 1 || *d.Builds[0].Result != string(store.BuildResultCancelled) {
		t.Fatalf("build: %+v", d.Builds)
	}
	nodeID := b.nodeID("builder-1")
	eventually(t, 30*time.Second, "the build container to be removed", func() bool { return buildContainers(t, nodeID) == 0 })
}

// TestAgentLostMidBuildRetriesElsewhere stops the agent running a build:
// the attempt ends as an infrastructure failure and the build is retried,
// and completed, on the other node.
func TestAgentLostMidBuildRetriesElsewhere(t *testing.T) {
	b := startBuildEnv(t, nil)
	second := b.joinBuilder("builder-2", b.primary.grpc)
	agents := map[string]*runningAgent{"builder-1": b.agent, "builder-2": second}
	b.createApp(b.alice, b.ws, "web")
	n := b.deploy(b.alice, b.ws, "web", project(t, slowDockerfile("retry-me", 20)))
	var d deploymentResp
	eventually(t, 2*time.Minute, "the first attempt to start", func() bool {
		d = b.deployment(b.alice, b.ws, "web", n)
		return len(d.Builds) == 1 && strings.Contains(b.buildLog(b.alice, b.ws, "web", n), "retry-me")
	})
	first := d.Builds[0].Node
	agents[first].stop()

	d = b.waitStatus(b.alice, b.ws, "web", n, 4*time.Minute, "built", "failed")
	if d.Status != "built" || len(d.Builds) != 2 {
		t.Fatalf("deployment %+v\nlog:\n%s", d, b.buildLog(b.alice, b.ws, "web", n))
	}
	if r := *d.Builds[0].Result; r != "infra_error" && r != "lost" {
		t.Fatalf("first attempt ended %s", r)
	}
	if d.Builds[1].Node == first || *d.Builds[1].Result != "succeeded" {
		t.Fatalf("second attempt %+v", d.Builds[1])
	}
	if log := b.buildLog(b.alice, b.ws, "web", n); !strings.Contains(log, "retrying on another node") {
		t.Fatalf("log does not explain the retry:\n%s", log)
	}
}

// TestRedeliveryAfterOwnerDiesBuildsOnce kills the control-plane instance
// that owns a deployment mid-build. Another instance reclaims the job
// from the stream and sees the build through: exactly one build.
func TestRedeliveryAfterOwnerDiesBuildsOnce(t *testing.T) {
	b := startQueueOnly(t, nil)
	a := b.primary
	other := b.startInstance(map[string]string{"NOOK_HTTP_ADDR": "127.0.0.1:0"})
	// The agent connects to the instance that will survive, so that the
	// build's result reaches a live instance whichever one owned the job.
	b.agent = b.joinBuilder("builder-1", other.grpc)
	b.createApp(b.alice, b.ws, "web")
	n := b.deploy(b.alice, b.ws, "web", project(t, slowDockerfile("redelivered", 15)))
	b.waitStatus(b.alice, b.ws, "web", n, 2*time.Minute, "building")

	rdb := redisClient(t)
	depID := ""
	if err := b.db.QueryRow(context.Background(), "SELECT id::text FROM deployments WHERE number = $1", n).Scan(&depID); err != nil {
		t.Fatal(err)
	}
	owner, err := rdb.Get(context.Background(), "nook:builds:owner:"+depID).Result()
	if err != nil {
		t.Fatalf("no owner: %v", err)
	}
	if owner == other.srv.Instance() {
		// Swap roles: stop the owner (other) and keep a, but the agent
		// then needs a live instance on its address.
		other.stop()
		b.base = a.base
		b.startInstance(map[string]string{"NOOK_HTTP_ADDR": "127.0.0.1:0", "NOOK_GRPC_ADDR": other.grpc})
	} else {
		a.stop()
		b.base = other.base
	}
	d := b.waitStatus(b.alice, b.ws, "web", n, 3*time.Minute, "built", "failed")
	if d.Status != "built" || len(d.Builds) != 1 {
		t.Fatalf("deployment %+v", d)
	}
	if b.count("SELECT count(*) FROM builds") != 1 {
		t.Fatal("more than one build")
	}
	// The dead owner's job is reclaimed by the survivor (redelivery) and
	// acknowledged without building again.
	eventually(t, 30*time.Second, "the dead owner's job to be reclaimed and acknowledged", func() bool {
		pending, err := rdb.XPending(context.Background(), "nook:builds:queue", "dispatchers").Result()
		return err == nil && pending.Count == 0
	})
	if b.count("SELECT count(*) FROM builds") != 1 {
		t.Fatal("the redelivered job built again")
	}
}

// buildContainers counts a node's build containers on the Docker daemon.
func buildContainers(t *testing.T, nodeID string) int {
	t.Helper()
	cli, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	list, err := cli.ContainerList(context.Background(), client.ContainerListOptions{
		All: true, Filters: client.Filters{}.Add("label", "nook.build.node="+nodeID),
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(list.Items)
}

// nodeID returns a node's ID by name.
func (b *buildEnv) nodeID(name string) string {
	b.t.Helper()
	var n struct {
		ID string `json:"id"`
	}
	b.as(b.alice, http.MethodGet, "/api/v1/nodes/"+name, nil).json(b.t, &n)
	return n.ID
}
