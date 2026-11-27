//go:build integration

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/activity"
)

// noIdlePass configures a control plane whose own idle pass does not run
// during a test (the longest interval allowed), so only the test's
// sleepIdle, with its injected clock, puts apps to sleep.
var noIdlePass = map[string]string{"NOOK_ROLLOUT_IDLE_INTERVAL": "10m"}

// setActivity records that app last received a request at t (as gateways
// do).
func setActivity(t *testing.T, app uuid.UUID, at time.Time) {
	t.Helper()
	err := redisClient(t).ZAdd(context.Background(), activity.Key, goredis.Z{Score: float64(at.UnixMilli()), Member: app.String()}).Err()
	if err != nil {
		t.Fatal(err)
	}
}

// sleepIdle runs the leader's idle pass as of now (an injected clock) and
// returns how many apps it put to sleep.
func (r *runtimeEnv) sleepIdle(now time.Time) int {
	r.t.Helper()
	n, after, err := r.primary.srv.rollout.SleepIdle(context.Background(), r.db, now)
	after.Run(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return n
}

// instanceOf returns the newest instance of an app: ID, state, node name,
// container ID and last healthy time.
type instanceRow struct {
	ID          uuid.UUID
	State       string
	Node        string
	ContainerID string
	LastHealthy *time.Time
	Cause       string
	CauseAt     *time.Time
}

func (r *runtimeEnv) newestInstance(appID uuid.UUID) instanceRow {
	r.t.Helper()
	var i instanceRow
	err := r.db.QueryRow(context.Background(), `
		SELECT id, state::text, node_name, coalesce(container_id, ''), last_healthy_at, cause, cause_at
		FROM app_instances WHERE app_id = $1 ORDER BY created_at DESC LIMIT 1`, appID).
		Scan(&i.ID, &i.State, &i.Node, &i.ContainerID, &i.LastHealthy, &i.Cause, &i.CauseAt)
	if err != nil {
		r.t.Fatal(err)
	}
	return i
}

// instance returns one instance by ID.
func (r *runtimeEnv) instance(id uuid.UUID) instanceRow {
	r.t.Helper()
	var i instanceRow
	err := r.db.QueryRow(context.Background(), `
		SELECT id, state::text, node_name, coalesce(container_id, ''), last_healthy_at, cause, cause_at
		FROM app_instances WHERE id = $1`, id).
		Scan(&i.ID, &i.State, &i.Node, &i.ContainerID, &i.LastHealthy, &i.Cause, &i.CauseAt)
	if err != nil {
		r.t.Fatal(err)
	}
	return i
}

// containerState returns a container's state ("running", "exited", ...)
// or "" if it does not exist.
func containerState(t *testing.T, id string) string {
	t.Helper()
	info, err := dockerClient(t).ContainerInspect(context.Background(), id, client.ContainerInspectOptions{})
	if err != nil {
		return ""
	}
	return string(info.Container.State.Status)
}

// containerFinishedAt is when the container last exited, by the Docker
// daemon's clock.
func containerFinishedAt(t *testing.T, id string) time.Time {
	t.Helper()
	info, err := dockerClient(t).ContainerInspect(context.Background(), id, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339Nano, info.Container.State.FinishedAt)
	if err != nil {
		t.Fatalf("container %s finished at %q: %v", id, info.Container.State.FinishedAt, err)
	}
	return at
}

// containerStarts counts the "start" events of app's containers after
// since (by the daemon's clock, to the nanosecond: a start a moment
// before must not count) and until now.
func containerStarts(t *testing.T, app uuid.UUID, since time.Time) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := dockerClient(t).Events(ctx, client.EventsListOptions{
		Since: fmt.Sprintf("%d.%09d", since.Unix(), since.Nanosecond()), Until: strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10),
		Filters: client.Filters{}.Add("type", string(events.ContainerEventType)).Add("event", "start").Add("label", "nook.app="+app.String()),
	})
	n := 0
	for {
		select {
		case <-res.Messages:
			n++
		case err := <-res.Err:
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("docker events: %v", err)
			}
			return n
		}
	}
}

// metricValue reads one line of a /metrics page ("name{labels}" as shown),
// or -1 if absent.
func metricValue(t *testing.T, url, line string) float64 {
	t.Helper()
	status, body := get(url)
	if status != http.StatusOK {
		t.Fatalf("GET %s: %d", url, status)
	}
	for l := range strings.SplitSeq(body, "\n") {
		if rest, ok := strings.CutPrefix(l, line+" "); ok {
			v, err := strconv.ParseFloat(rest, 64)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	return -1
}

// publicApp makes an app public (gateway tests without sign-in).
func (r *runtimeEnv) publicApp(slug string) {
	r.t.Helper()
	expectStatus(r.t, r.as(r.alice, http.MethodPut, appURL(r.ws, slug)+"/access", map[string]string{"mode": "public"}), http.StatusOK, "public "+slug)
}

// fill reserves all but freeMB of a node's app capacity for an app that
// runs nothing (a fixture instance of a never-released deployment), so
// placement sees the node as nearly full.
func (r *runtimeEnv) fill(node string, freeMB int64) {
	r.t.Helper()
	ctx := context.Background()
	var nodeID uuid.UUID
	var capacity, reserved int64
	err := r.db.QueryRow(ctx, `
		SELECT n.id, n.memory_total_bytes / 1048576 - 512,
		       coalesce((SELECT sum(memory_mb) FROM app_instances i WHERE i.node_id = n.id
		                 AND i.state IN ('starting', 'healthy', 'unhealthy', 'stopping')), 0)
		FROM nodes n WHERE n.name = $1`, node).Scan(&nodeID, &capacity, &reserved)
	if err != nil {
		r.t.Fatal(err)
	}
	hog := capacity - reserved - freeMB
	if hog <= 0 {
		r.t.Fatalf("node %s has only %d MB free", node, capacity-reserved)
	}
	slug := fmt.Sprintf("hog%d", time.Now().UnixNano()%1_000_000)
	r.createApp(r.alice, r.ws, slug)
	var appID, wsID, depID uuid.UUID
	err = r.db.QueryRow(ctx, `
		WITH a AS (SELECT a.id, a.workspace_id FROM apps a JOIN workspaces w ON w.id = a.workspace_id WHERE w.slug = $1 AND a.slug = $2)
		INSERT INTO deployments (app_id, number, status, source_key, source_sha256, source_size, upload_expires_at)
		SELECT a.id, 1, 'pending', 'k', decode(repeat('00', 32), 'hex'), 1, now() FROM a
		RETURNING app_id, (SELECT workspace_id FROM a), id`, r.ws, slug).Scan(&appID, &wsID, &depID)
	if err != nil {
		r.t.Fatal(err)
	}
	r.exec(`INSERT INTO app_instances (app_id, deployment_id, workspace_id, node_id, node_name, state, memory_mb, cpu_millicores, address)
		VALUES ($1, $2, $3, $4, $5, 'healthy', $6, 10, '127.0.0.1')`, appID, depID, wsID, nodeID, node, hog)
}
