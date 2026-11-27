//go:build integration

package server

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/appdb"
)

// TestAppDatabaseLifecycle: an app gets a database of its own and its
// DATABASE_URL; another app's role cannot reach it; WAL is archived to
// the object store within the archive timeout, encrypted; rotating the
// password invalidates the old one; a dump restores elsewhere; deleting
// drops database and role; no password reaches logs or API responses.
func TestAppDatabaseLifecycle(t *testing.T) {
	d := startDBEnv(t, nil)
	for _, slug := range []string{"alpha", "beta"} {
		d.newRuntimeApp(d.alice, d.ws, slug, nil)
		d.waitLive(d.alice, d.ws, slug, d.release(d.ws, slug))
	}
	_, alphaID := d.appIDs(d.ws, "alpha")
	_, betaID := d.appIDs(d.ws, "beta")

	// Provisioning: the first database also starts the server.
	in := d.createDatabase(d.ws, "alpha")
	if in.Name != appdb.DatabaseName(alphaID) || in.Server == nil || in.Server.Node != "builder-1" || in.Server.Generation != 1 {
		t.Fatalf("database: %+v", in)
	}
	alphaURL := d.appDatabaseURL(d.ws, "alpha")
	if !strings.Contains(alphaURL, "sslmode=require") || !strings.Contains(alphaURL, "/"+in.Name) {
		t.Fatalf("DATABASE_URL %q", redact(alphaURL))
	}
	var env struct {
		Items []struct {
			Key    string  `json:"key"`
			Value  *string `json:"value"`
			Secret bool    `json:"secret"`
		} `json:"items"`
	}
	d.as(d.alice, http.MethodGet, appURL(d.ws, "alpha")+"/env", nil).json(t, &env)
	if i := slices.IndexFunc(env.Items, func(e struct {
		Key    string  `json:"key"`
		Value  *string `json:"value"`
		Secret bool    `json:"secret"`
	}) bool {
		return e.Key == "DATABASE_URL"
	}); i < 0 || !env.Items[i].Secret || env.Items[i].Value != nil {
		t.Fatalf("DATABASE_URL must be a secret variable: %+v", env.Items)
	}
	// Users cannot overwrite the variable Nook manages.
	if r := d.as(d.alice, http.MethodPut, appURL(d.ws, "alpha")+"/env", map[string]any{"vars": map[string]string{"DATABASE_URL": "x"}, "secret": true}); r.status != http.StatusConflict {
		t.Fatalf("overwriting DATABASE_URL: %d %s", r.status, r.body)
	}
	// The app reaches its database through its own container.
	if out := d.appQuery(d.ws, "alpha", "CREATE TABLE notes (id serial PRIMARY KEY, body text NOT NULL)"); strings.HasPrefix(out, "error") && !strings.Contains(out, "no rows") {
		t.Fatalf("create table from the app: %s", out)
	}
	if out := d.appQuery(d.ws, "alpha", "INSERT INTO notes (body) VALUES ('first') RETURNING id::text"); out != "ok 1" {
		t.Fatalf("insert from the app: %s", out)
	}

	// Isolation: beta's role cannot connect to alpha's database, nor to
	// the server's own.
	d.createDatabase(d.ws, "beta")
	betaURL := d.appDatabaseURL(d.ws, "beta")
	for _, target := range []string{appdb.DatabaseName(alphaID), "postgres", "template1"} {
		other := strings.Replace(betaURL, "/"+appdb.DatabaseName(betaID)+"?", "/"+target+"?", 1)
		if conn, err := d.connect(other); err == nil {
			_ = conn.Close(context.Background())
			t.Fatalf("beta's role connected to %s", target)
		} else if !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("beta -> %s: %v", target, err)
		}
	}
	if out := d.appQuery(d.ws, "beta", "SELECT count(*)::text FROM pg_database WHERE datname = current_database()"); out != "ok 1" {
		t.Fatalf("beta's own database: %s", out)
	}

	// Archiving: a write is in the object store within archive_timeout
	// (plus the monitor's look), encrypted.
	su := d.superuser()
	walBefore, _ := lastArchived(t, su)
	if out := d.appQuery(d.ws, "alpha", "INSERT INTO notes (body) VALUES ('archived') RETURNING id::text"); out != "ok 2" {
		t.Fatalf("insert: %s", out)
	}
	wrote := time.Now()
	var wal string
	eventually(t, dbArchiveTimeout+15*time.Second, "the write to be archived", func() bool {
		var at *time.Time
		wal, at = lastArchived(t, su)
		return wal != walBefore && at != nil && at.After(wrote.Add(-time.Second))
	})
	took := time.Since(wrote)
	if took > dbArchiveTimeout+5*time.Second {
		t.Fatalf("archived after %s; archive_timeout is %s", took, dbArchiveTimeout)
	}
	t.Logf("a write was archived %s after it committed (archive_timeout %s)", took.Round(100*time.Millisecond), dbArchiveTimeout)
	objects := minioObjects(t, d.prefix)
	walKey := d.prefix + "/wal_005/" + wal + ".lz4"
	if !slices.Contains(objects, strings.TrimPrefix(walKey, d.prefix+"/")) {
		t.Fatalf("%s is not in the object store: %v", walKey, objects)
	}
	if !slices.ContainsFunc(objects, func(o string) bool { return strings.HasPrefix(o, "basebackups_005/base_") }) {
		t.Fatalf("no base backup after the first start: %v", objects)
	}
	data := minioObject(t, walKey)
	if len(data) < 64 || string(data[:4]) == "\x04\x22\x4d\x18" || strings.Contains(string(data), "archived") {
		t.Fatal("a WAL object is not encrypted (lz4 header or plaintext found)")
	}
	server := "nook-db-" + d.servers()[0].ID.String()
	walg := []string{"sh", "-c", "rm -f /tmp/seg && wal-g wal-fetch " + wal + " /tmp/seg"}
	if code, out := execIn(t, server, walg, nil, "WALG_LIBSODIUM_KEY="+strings.Repeat("ab", 32)); code == 0 {
		t.Fatalf("a wrong key decrypted the archive: %s", out)
	}
	if code, out := execIn(t, server, walg, nil, "WALG_LIBSODIUM_KEY="+backupKey(t)); code != 0 {
		t.Fatalf("the right key could not read the archive: %s", out)
	}

	// Rotation: the old password stops working; the app gets the new one.
	old, oldErr := d.connect(alphaURL)
	if oldErr != nil {
		t.Fatalf("connect with the current password: %v", oldErr)
	}
	_ = old.Close(context.Background())
	expectStatus(t, d.as(d.alice, http.MethodPost, dbURL(d.ws, "alpha")+"/rotate-password", nil), http.StatusOK, "rotate")
	if conn, err := d.connect(alphaURL); err == nil {
		_ = conn.Close(context.Background())
		t.Fatal("the old password still works")
	} else if !strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("old password: %v", err)
	}
	var rotated string
	eventually(t, 2*time.Minute, "alpha to get the new DATABASE_URL", func() bool {
		rotated = d.appDatabaseURL(d.ws, "alpha")
		return rotated != alphaURL
	})
	if out := d.appQuery(d.ws, "alpha", "SELECT count(*)::text FROM notes"); out != "ok 2" {
		t.Fatalf("alpha after rotation: %s", out)
	}

	// Dump: plain SQL that restores into another database.
	var dump struct {
		ID          string `json:"id"`
		State       string `json:"state"`
		Error       string `json:"error"`
		DownloadURL string `json:"download_url"`
	}
	d.as(d.alice, http.MethodPost, dbURL(d.ws, "alpha")+"/dumps", nil).json(t, &dump)
	eventually(t, time.Minute, "the dump", func() bool {
		d.as(d.alice, http.MethodGet, dbURL(d.ws, "alpha")+"/dumps/"+dump.ID, nil).json(t, &dump)
		if dump.State == "failed" {
			t.Fatalf("dump failed: %s", dump.Error)
		}
		return dump.State == "ready"
	})
	resp, err := http.Get(dump.DownloadURL) //nolint:noctx // a test download
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(sql), "CREATE TABLE public.notes") || !strings.Contains(string(sql), "archived") {
		t.Fatalf("dump:\n%.500s", sql)
	}
	if code, out := execIn(t, server, []string{"createdb", "scratch"}, nil); code != 0 {
		t.Fatal(out)
	}
	if code, out := execIn(t, server, []string{"psql", "-X", "-v", "ON_ERROR_STOP=1", "-q", "-d", "scratch", "-f", "-"}, sql); code != 0 {
		t.Fatalf("restore the dump: %s", out)
	}
	if code, out := execIn(t, server, []string{"psql", "-XtA", "-d", "scratch", "-c", "SELECT string_agg(body, ',' ORDER BY id) FROM notes"}, nil); code != 0 || strings.TrimSpace(out) != "first,archived" {
		t.Fatalf("restored rows: %d %q", code, out)
	}

	// Delete: database and role are gone, and so is DATABASE_URL.
	expectStatus(t, d.as(d.alice, http.MethodDelete, dbURL(d.ws, "beta"), nil), http.StatusAccepted, "delete")
	eventually(t, time.Minute, "beta's database to be dropped", func() bool {
		return d.as(d.alice, http.MethodGet, dbURL(d.ws, "beta"), nil).status == http.StatusNotFound
	})
	var roles, dbs int
	name := appdb.DatabaseName(betaID)
	if err := su.QueryRow(context.Background(), "SELECT (SELECT count(*) FROM pg_roles WHERE rolname = $1), (SELECT count(*) FROM pg_database WHERE datname = $1)", name).Scan(&roles, &dbs); err != nil || roles != 0 || dbs != 0 {
		t.Fatalf("after delete: %d roles, %d databases, %v", roles, dbs, err)
	}
	eventually(t, 2*time.Minute, "beta to lose DATABASE_URL", func() bool {
		code, _ := get(d.appBase(d.alice, d.ws, "beta") + "/env?k=DATABASE_URL")
		return code == http.StatusNotFound
	})
	if !slices.Contains(d.auditActions(), "database.create") || !slices.Contains(d.auditActions(), "database.rotate_password") ||
		!slices.Contains(d.auditActions(), "database.dump") || !slices.Contains(d.auditActions(), "database.delete") {
		t.Fatalf("audit: %v", d.auditActions())
	}

	// No password in logs or API responses.
	for _, dsn := range []string{alphaURL, rotated, betaURL} {
		pw := password(t, dsn)
		if strings.Contains(d.logs.String(), pw) {
			t.Fatal("a database password is in the control plane's log")
		}
		for _, path := range []string{dbURL(d.ws, "alpha"), appURL(d.ws, "alpha") + "/env", "/api/v1/admin/database"} {
			if r := d.as(d.alice, http.MethodGet, path, nil); strings.Contains(r.body, pw) {
				t.Fatalf("a database password is in GET %s", path)
			}
		}
	}
}
