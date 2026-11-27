//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/moby/moby/api/pkg/stdcopy"
	dockerclient "github.com/moby/moby/client"

	"github.com/the-asmit/nook/internal/appdb"
	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/testinfra"
)

// dbEnv is a runtime environment whose control plane runs app databases:
// the nook-postgres image built from this repository, backups in the
// shared MinIO under a prefix of the test's own.
type dbEnv struct {
	*runtimeEnv
	host    testinfra.DatabaseHost
	minioIP string
	prefix  string
}

// dbArchiveTimeout is the archive_timeout the tests use (the minimum).
const dbArchiveTimeout = 10 * time.Second

func startDBEnv(t *testing.T, overrides map[string]string) *dbEnv {
	t.Helper()
	ctx := context.Background()
	image, err := testinfra.BuildPostgresServerImage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	host, err := testinfra.DatabaseHostAddrs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	minioIP, err := shared.storage.MinIO.ContainerIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "appdb-it/" + strings.ToLower(rand.Text()[:10])
	env := map[string]string{
		"NOOK_APPDB_IMAGE": image, "NOOK_APPDB_S3_ENDPOINT": "http://" + net.JoinHostPort(minioIP, "9000"),
		"NOOK_APPDB_BACKUP_PREFIX": prefix, "NOOK_APPDB_ADMIN_HOST": host.Admin,
		"NOOK_APPDB_INTERVAL": "200ms", "NOOK_APPDB_MONITOR_INTERVAL": "1s",
		"NOOK_APPDB_ARCHIVE_TIMEOUT": dbArchiveTimeout.String(), "NOOK_APPDB_MEMORY_MB": "256",
	}
	maps.Copy(env, overrides)
	d := &dbEnv{host: host, minioIP: minioIP, prefix: prefix}
	d.runtimeEnv = startRuntimeEnvWith(t, env, d.newAgentOverrides(t))
	t.Cleanup(d.removeVolumes)
	return d
}

// newAgentOverrides configure an agent to host the server on its own port.
func (d *dbEnv) newAgentOverrides(t *testing.T) map[string]string {
	t.Helper()
	port, err := testinfra.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"NOOK_AGENT_DB_ADDR": d.host.App, "NOOK_AGENT_DB_PUBLISH_ADDR": d.host.Publish,
		"NOOK_AGENT_DB_PORT": strconv.Itoa(port), "NOOK_AGENT_DB_EGRESS_ALLOW": d.minioIP,
	}
}

// joinDBNode joins another node that can host the server (its own port).
func (d *dbEnv) joinDBNode(name string) *runningAgent {
	d.t.Helper()
	saved := d.agentOverrides
	d.agentOverrides = d.newAgentOverrides(d.t)
	defer func() { d.agentOverrides = saved }()
	return d.joinBuilder(name, d.primary.grpc)
}

// removeVolumes deletes the volumes of the test's database servers.
func (d *dbEnv) removeVolumes() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rows, err := d.db.Query(ctx, "SELECT id FROM app_db_servers")
	if err != nil {
		return
	}
	ids, _ := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	c := dockerClient(d.t)
	for _, id := range ids {
		_, _ = c.ContainerRemove(ctx, "nook-db-"+id.String(), dockerclient.ContainerRemoveOptions{Force: true})
		_, _ = c.VolumeRemove(ctx, "nook-db-"+id.String(), dockerclient.VolumeRemoveOptions{Force: true})
	}
}

// dbInfoView is GET .../database.
type dbInfoView struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Available bool   `json:"available"`
	LastError string `json:"last_error"`
	SizeBytes int64  `json:"size_bytes"`
	Server    *struct {
		Node           string     `json:"node"`
		State          string     `json:"state"`
		Generation     int32      `json:"generation"`
		LastArchivedAt *time.Time `json:"last_archived_at"`
		LastBackupAt   *time.Time `json:"last_backup_at"`
	} `json:"server"`
}

func dbURL(ws, app string) string { return appURL(ws, app) + "/database" }

// createDatabase creates an app's database and waits until it is ready.
func (d *dbEnv) createDatabase(ws, app string) dbInfoView {
	d.t.Helper()
	expectStatus(d.t, d.as(d.alice, http.MethodPost, dbURL(ws, app), nil), http.StatusAccepted, "create database for "+app)
	return d.waitDatabase(ws, app)
}

func (d *dbEnv) waitDatabase(ws, app string) dbInfoView {
	d.t.Helper()
	var in dbInfoView
	deadline := time.Now().Add(3 * time.Minute)
	for {
		d.as(d.alice, http.MethodGet, dbURL(ws, app), nil).json(d.t, &in)
		if in.State == "ready" && in.Available {
			return in
		}
		if time.Now().After(deadline) {
			d.t.Fatalf("the database of %s is not ready after 3m: %+v\n%s", app, in, d.dbDiagnosis())
		}
		select {
		case <-d.t.Context().Done():
			d.t.Fatal(d.t.Context().Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// dbDiagnosis describes the servers, the nodes' database fields and the
// control plane's app database log lines, for failure messages.
func (d *dbEnv) dbDiagnosis() string {
	var b strings.Builder
	servers := d.servers()
	for i := range servers {
		s := &servers[i]
		var lastErr string
		_ = d.db.QueryRow(context.Background(), "SELECT last_error FROM app_db_servers WHERE id = $1", s.ID).Scan(&lastErr)
		fmt.Fprintf(&b, "server generation %d: %s on %s (%s:%d) cause %s, last error %q\n", s.Generation, s.State, s.Node, s.Address, s.Port, s.Cause, lastErr)
	}
	rows, err := d.db.Query(context.Background(), "SELECT name, status::text, db_address, db_port, db_unavailable_reason FROM nodes ORDER BY name")
	if err == nil {
		for rows.Next() {
			var name, status, addr, reason string
			var port int32
			_ = rows.Scan(&name, &status, &addr, &port, &reason)
			fmt.Fprintf(&b, "node %s: %s, database %s:%d, unavailable %q\n", name, status, addr, port, reason)
		}
		rows.Close()
	}
	for line := range strings.SplitSeq(d.logs.String(), "\n") {
		if strings.Contains(line, "database") && (strings.Contains(line, `"level":"WARN"`) || strings.Contains(line, `"level":"ERROR"`) || strings.Contains(line, "placing")) {
			b.WriteString(line[:min(len(line), 500)] + "\n")
		}
	}
	return b.String()
}

// appDatabaseURL returns DATABASE_URL as the app's container sees it,
// once the deployment that carries it is live.
func (d *dbEnv) appDatabaseURL(ws, app string) string {
	d.t.Helper()
	var v string
	eventually(d.t, 2*time.Minute, app+" to see its DATABASE_URL", func() bool {
		a := d.app(d.alice, ws, app)
		if a.Health != "running" || a.Instance == nil || a.Instance.HostPort == nil {
			return false
		}
		code, body := get(d.appBase(d.alice, ws, app) + "/env?k=DATABASE_URL")
		v = body
		return code == http.StatusOK
	})
	return v
}

// appQuery runs sql through the app's own container and DATABASE_URL.
func (d *dbEnv) appQuery(ws, app, sql string) string {
	d.t.Helper()
	_, body := get(d.appBase(d.alice, ws, app) + "/db?sql=" + url.QueryEscape(sql))
	return body
}

// reachable rewrites a DATABASE_URL (the address apps use) to the address
// the test process reaches the server at.
func (d *dbEnv) reachable(dsn string) string {
	d.t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		d.t.Fatal(err)
	}
	u.Host = net.JoinHostPort(d.host.Admin, u.Port())
	return u.String()
}

// connect opens a connection from the test process.
func (d *dbEnv) connect(dsn string) (*pgx.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgx.Connect(ctx, d.reachable(dsn))
}

// superuser connects to the current server as the control plane does.
func (d *dbEnv) superuser() *pgx.Conn { return d.superuserTo("postgres") }

// superuserTo connects to database on the current server as the superuser.
func (d *dbEnv) superuserTo(database string) *pgx.Conn {
	d.t.Helper()
	ctx := context.Background()
	var id uuid.UUID
	var sealed []byte
	var version, port int32
	err := d.db.QueryRow(ctx, `SELECT id, superuser_password, password_key_version, port FROM app_db_servers
		WHERE state = 'running'`).Scan(&id, &sealed, &version, &port)
	if err != nil {
		d.t.Fatalf("no running server: %v", err)
	}
	k, err := secrets.ParseKeyring(testSecretsKey)
	if err != nil {
		d.t.Fatal(err)
	}
	pw, err := k.Open(int(version), secrets.DatabaseSuperuserAAD(id), sealed)
	if err != nil {
		d.t.Fatal(err)
	}
	ca, _, err := pki.LoadOrCreateCA(shared.caPath)
	if err != nil {
		d.t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		d.t.Fatal(err)
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database = d.host.Admin, uint16(port), appdb.Superuser, string(pw), database //nolint:gosec // G115: a port.
	cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca.Pool(), ServerName: d.host.Admin}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		d.t.Fatal(err)
	}
	d.t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// serverRow is one generation of the server.
type serverRow struct {
	ID         uuid.UUID
	Generation int32
	State      string
	Node       string
	Address    string
	Port       int32
	Cause      string
	CauseAt    time.Time
	RunningAt  *time.Time
	StoppedAt  *time.Time
}

func (d *dbEnv) servers() []serverRow {
	d.t.Helper()
	rows, err := d.db.Query(context.Background(), `SELECT id, generation, state::text, node_name, address, port, cause, cause_at, running_at, stopped_at
		FROM app_db_servers ORDER BY generation`)
	if err != nil {
		d.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (serverRow, error) {
		var s serverRow
		scanErr := r.Scan(&s.ID, &s.Generation, &s.State, &s.Node, &s.Address, &s.Port, &s.Cause, &s.CauseAt, &s.RunningAt, &s.StoppedAt)
		return s, scanErr
	})
	if err != nil {
		d.t.Fatal(err)
	}
	return out
}

// waitServer waits until generation gen runs and returns it.
func (d *dbEnv) waitServer(gen int32, within time.Duration) serverRow {
	d.t.Helper()
	var s serverRow
	eventually(d.t, within, fmt.Sprintf("server generation %d to run", gen), func() bool {
		rows := d.servers()
		for i := range rows {
			if rows[i].Generation == gen && rows[i].State == "running" {
				s = rows[i]
				return true
			}
		}
		return false
	})
	return s
}

// lastArchived is the server's last archived segment and when.
func lastArchived(t *testing.T, conn *pgx.Conn) (string, *time.Time) {
	t.Helper()
	var wal string
	var at *time.Time
	if err := conn.QueryRow(context.Background(), `SELECT coalesce(last_archived_wal, ''), last_archived_time FROM pg_stat_archiver`).Scan(&wal, &at); err != nil {
		t.Fatal(err)
	}
	return wal, at
}

// minioObjects lists object names under a prefix of the "nook" bucket.
func minioObjects(t *testing.T, prefix string) []string {
	t.Helper()
	m := shared.storage.MinIO
	alias := fmt.Sprintf("http://%s:%s@127.0.0.1:9000", m.AccessKey, m.SecretKey)
	code, out, err := m.Exec(context.Background(), []string{"env", "MC_HOST_l=" + alias, "mc", "ls", "--recursive", "l/nook/" + prefix + "/"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, out)
	if code != 0 {
		t.Fatalf("mc ls exited %d: %s", code, buf.String())
	}
	var names []string
	for line := range strings.SplitSeq(buf.String(), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			names = append(names, f[len(f)-1])
		}
	}
	return names
}

// minioObject returns an object's bytes.
func minioObject(t *testing.T, key string) []byte {
	t.Helper()
	m := shared.storage.MinIO
	alias := fmt.Sprintf("http://%s:%s@127.0.0.1:9000", m.AccessKey, m.SecretKey)
	code, out, err := m.Exec(context.Background(), []string{"env", "MC_HOST_l=" + alias, "mc", "cat", "l/nook/" + key})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, out)
	if code != 0 {
		t.Fatalf("mc cat exited %d", code)
	}
	return buf.Bytes()
}

// execIn runs a command in a container with stdin, returning its exit
// code and combined output.
func execIn(t *testing.T, container string, cmd []string, stdin []byte, env ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := dockerClient(t)
	created, err := c.ExecCreate(ctx, container, dockerclient.ExecCreateOptions{Cmd: cmd, Env: env, AttachStdin: stdin != nil, AttachStdout: true, AttachStderr: true})
	if err != nil {
		t.Fatal(err)
	}
	att, err := c.ExecAttach(ctx, created.ID, dockerclient.ExecAttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer att.Close()
	if stdin != nil {
		go func() {
			_, _ = att.Conn.Write(stdin)
			_ = att.CloseWrite()
		}()
	}
	var out bytes.Buffer
	_, _ = stdcopy.StdCopy(&out, &out, att.Reader)
	for {
		ins, err := c.ExecInspect(ctx, created.ID, dockerclient.ExecInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !ins.Running {
			return ins.ExitCode, out.String()
		}
		select {
		case <-ctx.Done():
			t.Fatal("exec did not finish")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// backupKey is the hex backup encryption key the control plane derives.
func backupKey(t *testing.T) string {
	t.Helper()
	k, err := secrets.ParseKeyring(testSecretsKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := k.Derive(1, "appdb-backups/v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key)
}

// password is the password in a DATABASE_URL.
func password(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pw, ok := u.User.Password()
	if !ok || len(pw) < 32 {
		t.Fatalf("no password in the URL")
	}
	return pw
}

// redact hides a DATABASE_URL's password for messages.
func redact(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "(unparsable)"
	}
	return u.Redacted()
}

// volumeExists reports whether a Docker volume exists.
func volumeExists(t *testing.T, name string) bool {
	t.Helper()
	_, err := dockerClient(t).VolumeInspect(context.Background(), name, dockerclient.VolumeInspectOptions{})
	return err == nil
}

// appQueryAt runs sql from the app's container against another database
// URL than its own.
func (d *dbEnv) appQueryAt(ws, app, sql, dsn string) string {
	d.t.Helper()
	_, body := get(d.appBase(d.alice, ws, app) + "/db?sql=" + url.QueryEscape(sql) + "&url=" + url.QueryEscape(dsn))
	return body
}

func contains(list []string, s string) bool { return slices.Contains(list, s) }
