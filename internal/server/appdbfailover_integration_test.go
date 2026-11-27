//go:build integration

package server

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/agent"
)

// dbFailoverEnv: two nodes that can host the server, the server placed on
// builder-1 (labeled), and an app with a database holding two notes that
// are archived.
func dbFailoverEnv(t *testing.T) (*dbEnv, string) {
	t.Helper()
	d := startDBEnv(t, map[string]string{"NOOK_ROLLOUT_RELOCATE_INTERVAL": "200ms"})
	expectStatus(t, d.as(d.alice, http.MethodPut, "/api/v1/nodes/builder-1/labels", map[string]any{"labels": map[string]string{"nook.database": "true"}}),
		http.StatusOK, "label builder-1")
	d.joinDBNode("node-b")
	d.newRuntimeApp(d.alice, d.ws, "notes", nil)
	d.waitLive(d.alice, d.ws, "notes", d.release(d.ws, "notes"))
	d.createDatabase(d.ws, "notes")
	if s := d.servers(); len(s) != 1 || s[0].Node != "builder-1" {
		t.Fatalf("servers: %+v", s)
	}
	url := d.appDatabaseURL(d.ws, "notes")
	for _, q := range []string{
		"CREATE TABLE notes (id serial PRIMARY KEY, body text NOT NULL)",
		"INSERT INTO notes (body) VALUES ('one'), ('two') RETURNING 'x'",
	} {
		if out := d.appQuery(d.ws, "notes", q); strings.HasPrefix(out, "error") && !strings.Contains(out, "no rows") {
			t.Fatalf("%s: %s", q, out)
		}
	}
	return d, url
}

// waitRepointed waits until the app runs with a DATABASE_URL for s.
func (d *dbEnv) waitRepointed(app string, s *serverRow) string {
	d.t.Helper()
	var url string
	eventually(d.t, 3*time.Minute, app+" to be re-pointed to generation "+strconv.Itoa(int(s.Generation)), func() bool {
		url = d.appDatabaseURL(d.ws, app)
		return strings.Contains(url, ":"+strconv.Itoa(int(s.Port))+"/") && d.app(d.alice, d.ws, app).Health == "running"
	})
	return url
}

// TestAppDatabaseFailoverAfterNodeDeath: the node hosting the server dies
// (its container keeps running, as in a partition); the leader restores
// the server on the other node from the backups, the archived rows are
// there, and the app is re-pointed and healthy. The old server is
// unreachable for apps, and when its node returns its container is
// stopped and its volume kept until an admin removes it.
func TestAppDatabaseFailoverAfterNodeDeath(t *testing.T) {
	d, before := dbFailoverEnv(t)
	gen1 := d.servers()[0]
	su := d.superuser()
	wal, _ := lastArchived(t, su)
	eventually(t, dbArchiveTimeout+15*time.Second, "the notes to be archived", func() bool {
		w, _ := lastArchived(t, su)
		return w != wal
	})
	// Written after the last archive: may be lost (RPO = archive_timeout).
	_ = d.appQuery(d.ws, "notes", "INSERT INTO notes (body) VALUES ('maybe') RETURNING 'x'")

	d.agent.stop()
	if ok, _ := d.agent.exited(15 * time.Second); !ok {
		t.Fatal("the agent did not stop")
	}
	killed := time.Now()
	// Both nodes share this machine's iptables: the dead node's rules
	// (which still allow only the old server) would also filter node-b's
	// apps. On separate machines they could not; remove them.
	if err := agent.RemoveFirewall(t.Context(), d.agent.cfg, quietLogger); err != nil {
		t.Fatal(err)
	}
	gen2 := d.waitServer(2, 4*time.Minute)
	sinceKill := time.Since(killed)
	if gen2.Node != "node-b" || gen2.Cause != "failover" || gen2.RunningAt == nil {
		t.Fatalf("generation 2: %+v", gen2)
	}
	restore := gen2.RunningAt.Sub(gen2.CauseAt)
	t.Logf("database failover: node declared dead -> restored server running in %s (%s after the agent died)",
		restore.Round(100*time.Millisecond), sinceKill.Round(100*time.Millisecond))
	if v := metricValue(t, d.base+"/metrics", `nook_appdb_failover_seconds_count{cause="failover"}`); v != 1 {
		t.Fatalf("failover metric = %v", v)
	}

	after := d.waitRepointed("notes", &gen2)
	if after == before {
		t.Fatal("DATABASE_URL did not change")
	}
	out := d.appQuery(d.ws, "notes", "SELECT string_agg(body, ',' ORDER BY id) FROM notes WHERE body <> 'maybe'")
	if out != "ok one,two" {
		t.Fatalf("archived rows after the restore: %s", out)
	}
	// The old server still runs on the dead node, but apps cannot reach
	// it: the firewall allows only the current endpoint.
	if state := containerState(t, "nook-db-"+gen1.ID.String()); state != "running" {
		t.Fatalf("the old server is %q; the test wants it running to show it is not used", state)
	}
	if out := d.appQueryAt(d.ws, "notes", "SELECT 'reached'", before); !strings.HasPrefix(out, "error") {
		t.Fatalf("the app reached the replaced server: %s", out)
	}

	// The node returns: the old server is stopped (fenced), its volume kept.
	cfg := agentConfigWith(t, d.agentState, d.agentOverrides)
	runConfiguredAgent(t, &cfg, quietLogger)
	eventually(t, time.Minute, "the old server to be stopped", func() bool {
		s := d.servers()[0]
		return s.State == "fenced" && s.StoppedAt != nil && containerState(t, "nook-db-"+gen1.ID.String()) != "running"
	})
	if !volumeExists(t, "nook-db-"+gen1.ID.String()) {
		t.Fatal("the old server's volume must stay until an admin removes it")
	}
	if out := d.appQuery(d.ws, "notes", "SELECT count(*)::text FROM notes WHERE body <> 'maybe'"); out != "ok 2" {
		t.Fatalf("after the node returned: %s", out)
	}
	expectStatus(t, d.as(d.alice, http.MethodDelete, "/api/v1/admin/database/servers/"+gen2.ID.String(), nil), http.StatusConflict, "remove the current server")
	expectStatus(t, d.as(d.alice, http.MethodDelete, "/api/v1/admin/database/servers/"+gen1.ID.String(), nil), http.StatusNoContent, "remove the old server")
	eventually(t, time.Minute, "the old volume to be removed", func() bool { return !volumeExists(t, "nook-db-"+gen1.ID.String()) })
}

// TestPlannedDatabaseFailoverLosesNothing: rows committed a moment before
// a planned move (not archived yet by archive_timeout) are all there
// after it, thanks to the clean shutdown and final archive.
func TestPlannedDatabaseFailoverLosesNothing(t *testing.T) {
	d, _ := dbFailoverEnv(t)
	const n = 50
	if out := d.appQuery(d.ws, "notes", "INSERT INTO notes (body) SELECT 'row ' || g FROM generate_series(1, "+strconv.Itoa(n)+") g RETURNING 'x'"); strings.HasPrefix(out, "error") && !strings.Contains(out, "no rows") {
		t.Fatalf("insert: %s", out)
	}
	start := time.Now()
	expectStatus(t, d.as(d.alice, http.MethodPost, "/api/v1/admin/database/failover", map[string]string{"to": "node-b"}), http.StatusAccepted, "failover")
	gen2 := d.waitServer(2, 4*time.Minute)
	if gen2.Node != "node-b" || gen2.Cause != "planned" {
		t.Fatalf("generation 2: %+v", gen2)
	}
	var finalWAL string
	if err := d.db.QueryRow(t.Context(), "SELECT final_wal FROM app_db_servers WHERE generation = 1").Scan(&finalWAL); err != nil || finalWAL == "" {
		t.Fatalf("final WAL %q, %v", finalWAL, err)
	}
	d.waitRepointed("notes", &gen2)
	if out := d.appQuery(d.ws, "notes", "SELECT count(*)::text FROM notes"); out != "ok "+strconv.Itoa(n+2) {
		t.Fatalf("rows after the planned failover: %s (want %d)", out, n+2)
	}
	t.Logf("planned failover: %d of %d rows (written just before) kept; server moved in %s", n+2, n+2, time.Since(start).Round(100*time.Millisecond))
	if v := metricValue(t, d.base+"/metrics", `nook_appdb_failover_seconds_count{cause="planned"}`); v != 1 {
		t.Fatalf("planned failover metric = %v", v)
	}
	if !contains(d.auditActions(), "database.failover") {
		t.Fatal("the failover was not audited")
	}
}

// TestDatabaseEndpointsAreTenantScoped: non-members get 404 for every
// database endpoint, members may only view, instance-admin endpoints
// refuse everyone else, and the workspace quota applies.
func TestDatabaseEndpointsAreTenantScoped(t *testing.T) {
	b := startQueueOnly(t, map[string]string{"NOOK_APPDB_IMAGE": "nook-postgres:it", "NOOK_APPDB_ADMIN_HOST": "127.0.0.1"})
	mallory := b.newUser("mallory@nook.test")
	bob := b.newUser("bob@nook.test")
	expectStatus(t, b.as(b.alice, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Acme", "slug": "acme"}), 201, "create workspace")
	b.addMember("acme", bob, "member")
	b.createApp(b.alice, "acme", "web")
	dump := "/dumps/" + uuid.NewV7().String()
	calls := []struct{ method, path string }{
		{http.MethodGet, ""}, {http.MethodPost, ""}, {http.MethodDelete, ""},
		{http.MethodPost, "/rotate-password"}, {http.MethodPost, "/dumps"}, {http.MethodGet, dump},
	}
	for _, c := range calls {
		got := b.as(mallory, c.method, dbURL("acme", "web")+c.path, nil)
		missing := b.as(mallory, c.method, dbURL("acme", "nope")+c.path, nil)
		if got.status != http.StatusNotFound || got.errorCode(t) != missing.errorCode(t) {
			t.Errorf("outsider %s %s: %d %s", c.method, c.path, got.status, got.body)
		}
	}
	if r := b.as(bob, http.MethodGet, dbURL("acme", "web"), nil); r.status != http.StatusNotFound || !strings.Contains(r.body, "no database") {
		t.Errorf("member views (no database yet): %d %s", r.status, r.body)
	}
	for _, c := range calls[1:] {
		expectStatus(t, b.as(bob, c.method, dbURL("acme", "web")+c.path, nil), http.StatusForbidden, "member "+c.method+" "+c.path)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/admin/database", nil},
		{http.MethodPost, "/api/v1/admin/database/failover", map[string]string{"to": "x"}},
		{http.MethodDelete, "/api/v1/admin/database/servers/" + uuid.NewV7().String(), nil},
		{http.MethodPut, "/api/v1/nodes/x/labels", map[string]any{"labels": map[string]string{}}},
	} {
		expectStatus(t, b.as(bob, c.method, c.path, c.body), http.StatusForbidden, "non-admin "+c.method+" "+c.path)
	}
	var status struct {
		Enabled bool `json:"enabled"`
	}
	b.as(b.alice, http.MethodGet, "/api/v1/admin/database", nil).json(t, &status)
	if !status.Enabled {
		t.Fatal("app databases should be enabled")
	}
	expectStatus(t, b.as(b.alice, http.MethodPut, "/api/v1/admin/workspaces/acme/quota", map[string]any{"max_apps": 20, "max_concurrent_builds": 2, "max_databases": 0}), 200, "quota")
	if r := b.as(b.alice, http.MethodPost, dbURL("acme", "web"), nil); r.status != http.StatusConflict || r.errorCode(t) != "quota_exceeded" {
		t.Fatalf("over quota: %d %s", r.status, r.body)
	}
}
