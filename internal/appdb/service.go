package appdb

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Info describes an app's database. It never holds the password.
type Info struct {
	App             string      `json:"app"`
	Name            string      `json:"name"`
	State           string      `json:"state"`
	Available       bool        `json:"available"`
	SizeBytes       int64       `json:"size_bytes"`
	Connections     int32       `json:"connections"`
	ConnectionLimit int32       `json:"connection_limit"`
	LastError       string      `json:"last_error,omitempty"`
	CreatedAt       time.Time   `json:"created_at"`
	ReadyAt         *time.Time  `json:"ready_at,omitempty"`
	PasswordRotated *time.Time  `json:"password_rotated_at,omitempty"`
	Server          *ServerInfo `json:"server,omitempty"`
}

// ServerInfo is what members see of the server.
type ServerInfo struct {
	Node           string     `json:"node"`
	State          string     `json:"state"`
	Generation     int32      `json:"generation"`
	LastArchivedAt *time.Time `json:"last_archived_at,omitempty"`
	LastArchived   string     `json:"last_archived_wal,omitempty"`
	LastBackupAt   *time.Time `json:"last_backup_at,omitempty"`
	ArchiveFailed  int64      `json:"archive_failures"`
}

func serverInfo(s *store.AppDbServer) *ServerInfo {
	return &ServerInfo{
		Node: s.NodeName, State: string(s.State), Generation: s.Generation, LastArchivedAt: s.LastArchivedAt,
		LastArchived: s.LastArchivedWal, LastBackupAt: s.LastBackupAt, ArchiveFailed: s.ArchiveFailedCount,
	}
}

var (
	errNotConfigured = apperr.Conflict("databases_not_configured", "app databases are not set up on this installation (NOOK_APPDB_IMAGE)")
	errNoDatabase    = apperr.NotFound("the app has no database")
	errUnavailable   = apperr.Conflict("database_unavailable", "the app database server is not running right now; try again shortly")
)

// resolve finds an app through the actor's membership (404 otherwise)
// and requires minRole.
func resolve(ctx context.Context, q *store.Queries, actor workspace.Actor, wsSlug, appSlug string, minRole store.WorkspaceRole) (workspace.View, store.App, error) {
	v, err := workspace.Resolve(ctx, q, actor, wsSlug)
	if err != nil {
		return v, store.App{}, err
	}
	if !apps.ValidSlug(appSlug) {
		return v, store.App{}, apperr.NotFound("app not found")
	}
	app, err := q.GetApp(ctx, store.GetAppParams{WorkspaceID: v.Workspace.ID, Slug: appSlug})
	if store.IsNotFound(err) {
		return v, store.App{}, apperr.NotFound("app not found")
	}
	if err != nil {
		return v, store.App{}, fmt.Errorf("look up app: %w", err)
	}
	if !v.Allows(minRole) {
		return v, store.App{}, apperr.Forbidden("only workspace admins and owners can manage app databases")
	}
	return v, app, nil
}

// Create asks for a database for the app (admins and owners). The leader
// creates it once the server runs; the app then gets DATABASE_URL and is
// redeployed without a rebuild.
func (c *Controller) Create(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (Info, error) {
	if !c.cfg.Enabled() {
		return Info{}, errNotConfigured
	}
	pw, pwErr := newPassword()
	if pwErr != nil {
		return Info{}, pwErr
	}
	var out Info
	err := c.Store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug, store.WorkspaceRoleAdmin)
		if err != nil {
			return err
		}
		if _, lockErr := q.LockWorkspace(ctx, v.Workspace.ID); lockErr != nil {
			return fmt.Errorf("lock workspace: %w", lockErr)
		}
		if _, getErr := q.GetAppDatabase(ctx, app.ID); getErr == nil {
			return apperr.Conflict("database_exists", "the app already has a database")
		} else if !store.IsNotFound(getErr) {
			return fmt.Errorf("read the database: %w", getErr)
		}
		quota, err := c.Apps.QuotaFor(ctx, q, v.Workspace.ID)
		if err != nil {
			return err
		}
		n, err := q.CountWorkspaceDatabases(ctx, v.Workspace.ID)
		if err != nil {
			return fmt.Errorf("count databases: %w", err)
		}
		if n >= int64(quota.MaxDatabases) {
			return apperr.Conflict("quota_exceeded", "this workspace may have at most %d databases", quota.MaxDatabases)
		}
		if diskErr := c.checkDisk(ctx, q); diskErr != nil {
			return diskErr
		}
		sealed, version, err := c.Keyring.Seal(secrets.DatabasePasswordAAD(app.ID), []byte(pw))
		if err != nil {
			return err
		}
		d, err := q.CreateAppDatabase(ctx, store.CreateAppDatabaseParams{
			AppID: app.ID, WorkspaceID: v.Workspace.ID, Name: DatabaseName(app.ID), Password: sealed,
			PasswordKeyVersion: int32(version), ConnectionLimit: c.cfg.ConnectionLimit, CreatedBy: &actor.UserID, //nolint:gosec // G115: versions are at most 1e6.
		})
		if err != nil {
			return fmt.Errorf("record the database: %w", err)
		}
		out = c.info(ctx, q, &app, &d)
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionDatabaseCreate,
			TargetType: audit.TargetApp, TargetID: app.ID.String(), Metadata: map[string]any{"app": app.Slug, "database": d.Name},
		})
	})
	return out, err
}

// checkDisk refuses new databases while the server's node is nearly full
// (PostgreSQL cannot cap one database's size, so the disk is the limit).
func (c *Controller) checkDisk(ctx context.Context, q *store.Queries) error {
	srv, err := q.CurrentDBServer(ctx)
	if store.IsNotFound(err) || (err == nil && srv.NodeID == nil) {
		return nil // placement requires free disk
	}
	if err != nil {
		return fmt.Errorf("read the database server: %w", err)
	}
	node, err := q.GetLiveNodeByID(ctx, *srv.NodeID)
	if store.IsNotFound(err) {
		return nil // the server is moving to another node
	}
	if err != nil {
		return fmt.Errorf("read the server's node: %w", err)
	}
	if !diskOK(node.DiskFreeBytes, node.DiskTotalBytes, c.cfg.MinFreeDiskPercent) {
		return apperr.Conflict("database_disk_full", "the app database server's disk is nearly full (less than %d%% free); new databases are refused", c.cfg.MinFreeDiskPercent)
	}
	return nil
}

// Get describes the app's database (any member).
func (c *Controller) Get(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (Info, error) {
	q := c.Store.Queries
	_, app, err := resolve(ctx, q, actor, wsSlug, appSlug, store.WorkspaceRoleMember)
	if err != nil {
		return Info{}, err
	}
	d, err := q.GetAppDatabase(ctx, app.ID)
	if store.IsNotFound(err) {
		return Info{}, errNoDatabase
	}
	if err != nil {
		return Info{}, fmt.Errorf("read the database: %w", err)
	}
	return c.info(ctx, q, &app, &d), nil
}

func (c *Controller) info(ctx context.Context, q *store.Queries, app *store.App, d *store.AppDatabase) Info {
	in := Info{
		App: app.Slug, Name: d.Name, State: string(d.State), SizeBytes: d.SizeBytes, Connections: d.Connections,
		ConnectionLimit: d.ConnectionLimit, LastError: d.LastError, CreatedAt: d.CreatedAt, ReadyAt: d.ReadyAt,
		PasswordRotated: d.PasswordRotatedAt,
	}
	if srv, err := q.CurrentDBServer(ctx); err == nil {
		in.Server = serverInfo(&srv)
		in.Available = d.State == store.AppDatabaseStateReady && srv.State == store.AppDbServerStateRunning
	}
	return in
}

// Unavailable reports whether the app has a database that cannot be used
// now (its server is down or being restored): its state shows "database
// unavailable".
func (c *Controller) Unavailable(ctx context.Context, appID uuid.UUID) bool {
	d, err := c.Store.GetAppDatabase(ctx, appID)
	if err != nil || d.State != store.AppDatabaseStateReady {
		return false
	}
	srv, err := c.Store.CurrentDBServer(ctx)
	return err != nil || srv.State != store.AppDbServerStateRunning
}

// readyDatabase returns the app's ready database and the running server.
func (c *Controller) readyDatabase(ctx context.Context, q *store.Queries, app *store.App) (store.AppDatabase, store.AppDbServer, error) {
	d, err := q.LockAppDatabase(ctx, app.ID)
	if store.IsNotFound(err) {
		return d, store.AppDbServer{}, errNoDatabase
	}
	if err != nil {
		return d, store.AppDbServer{}, fmt.Errorf("read the database: %w", err)
	}
	if d.State != store.AppDatabaseStateReady {
		return d, store.AppDbServer{}, apperr.Conflict("database_not_ready", "the database is %s", d.State)
	}
	srv, err := q.CurrentDBServer(ctx)
	if err != nil || srv.State != store.AppDbServerStateRunning {
		return d, srv, errUnavailable
	}
	return d, srv, nil
}

// RotatePassword gives the app's role a new password and the app a new
// DATABASE_URL (redeployed without a rebuild); the old password stops
// working at once (admins and owners).
func (c *Controller) RotatePassword(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (Info, error) {
	if !c.cfg.Enabled() {
		return Info{}, errNotConfigured
	}
	pw, pwErr := newPassword()
	if pwErr != nil {
		return Info{}, pwErr
	}
	verifier, vErr := scramVerifier(pw)
	if vErr != nil {
		return Info{}, vErr
	}
	var out Info
	var dep *store.Deployment
	err := c.Store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug, store.WorkspaceRoleAdmin)
		if err != nil {
			return err
		}
		d, srv, err := c.readyDatabase(ctx, q, &app)
		if err != nil {
			return err
		}
		sealed, version, err := c.Keyring.Seal(secrets.DatabasePasswordAAD(app.ID), []byte(pw))
		if err != nil {
			return err
		}
		if setErr := q.SetAppDatabasePassword(ctx, store.SetAppDatabasePasswordParams{AppID: app.ID, Password: sealed, PasswordKeyVersion: int32(version)}); setErr != nil { //nolint:gosec // G115: versions are at most 1e6.
			return fmt.Errorf("store the password: %w", setErr)
		}
		if dep, err = c.Apps.SetManagedEnv(ctx, q, app.ID, apps.DatabaseURLKey, DatabaseURL(d.Name, pw, srv.Address, srv.Port), &actor.UserID); err != nil {
			return err
		}
		if auditErr := audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionDatabaseRotatePassword,
			TargetType: audit.TargetApp, TargetID: app.ID.String(), Metadata: map[string]any{"app": app.Slug, "database": d.Name},
		}); auditErr != nil {
			return auditErr
		}
		// Last, inside the transaction: if the server refuses, nothing
		// above is committed; if the commit then fails, the app keeps
		// its old password until rotated again.
		adm, err := c.connect(ctx, &srv)
		if err != nil {
			return errUnavailable
		}
		defer adm.close(ctx)
		if err := adm.setPassword(ctx, d.Name, verifier); err != nil {
			return fmt.Errorf("change the password on the server: %w", err)
		}
		out = c.info(ctx, q, &app, &d)
		return nil
	})
	if err != nil {
		return Info{}, err
	}
	c.release(ctx, dep)
	return out, nil
}

// Delete drops the app's database and role (admins and owners); its
// backups age out with the retention period.
func (c *Controller) Delete(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) error {
	return c.Store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug, store.WorkspaceRoleAdmin)
		if err != nil {
			return err
		}
		d, err := q.MarkAppDatabaseDeleting(ctx, app.ID)
		if store.IsNotFound(err) {
			if _, getErr := q.GetAppDatabase(ctx, app.ID); getErr == nil {
				return nil // already being deleted
			}
			return errNoDatabase
		}
		if err != nil {
			return fmt.Errorf("mark the database for deletion: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionDatabaseDelete,
			TargetType: audit.TargetApp, TargetID: app.ID.String(), Metadata: map[string]any{"app": app.Slug, "database": d.Name},
		})
	})
}

// Dump is a database export.
type Dump struct {
	ID          uuid.UUID  `json:"id"`
	State       string     `json:"state"`
	SizeBytes   int64      `json:"size_bytes"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	DownloadURL string     `json:"download_url,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

// downloadTTL bounds a dump's download URL.
const downloadTTL = 5 * time.Minute

// CreateDump starts a plain-SQL dump of the app's database on the
// server's node (admins and owners: it exports the data).
func (c *Controller) CreateDump(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (Dump, error) {
	if !c.cfg.Enabled() {
		return Dump{}, errNotConfigured
	}
	var d store.AppDbDump
	var srv store.AppDbServer
	var db store.AppDatabase
	err := c.Store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug, store.WorkspaceRoleAdmin)
		if err != nil {
			return err
		}
		if db, srv, err = c.readyDatabase(ctx, q, &app); err != nil {
			return err
		}
		id := uuid.NewV7()
		d, err = q.CreateDBDump(ctx, store.CreateDBDumpParams{
			AppID: app.ID, WorkspaceID: v.Workspace.ID, ObjectKey: "appdb-dumps/" + id.String() + ".sql",
			CreatedBy: &actor.UserID, ExpiresAt: c.now().Add(dumpGrace + c.cfg.DumpTTL),
		})
		if err != nil {
			return fmt.Errorf("record the dump: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionDatabaseDump,
			TargetType: audit.TargetApp, TargetID: app.ID.String(), Metadata: map[string]any{"app": app.Slug, "dump": d.ID.String()},
		})
	})
	if err != nil {
		return Dump{}, err
	}
	cmd := &agentv1.Command{Kind: &agentv1.Command_DumpDatabase{DumpDatabase: &agentv1.DumpDatabaseCommand{
		DumpId: d.ID.String(), ServerId: srv.ID.String(), Database: db.Name, MaxBytes: c.cfg.DumpMaxBytes,
	}}}
	res, err := c.Commander.Dispatch(ctx, *srv.NodeID, cmd, dispatchTimeout)
	if err == nil && res.GetError() != nil {
		err = errors.New(res.GetError().GetMessage())
	}
	if err != nil {
		_ = c.Store.DBDumpFailed(ctx, store.DBDumpFailedParams{ID: d.ID, Error: truncate("could not start: "+err.Error(), 1000)})
		return Dump{}, apperr.Conflict("dump_failed", "the database server's node could not start the dump")
	}
	return dumpView(&d, ""), nil
}

// GetDump describes a dump; a finished one carries a short-lived URL to
// download it.
func (c *Controller) GetDump(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, id uuid.UUID) (Dump, error) {
	q := c.Store.Queries
	_, app, err := resolve(ctx, q, actor, wsSlug, appSlug, store.WorkspaceRoleAdmin)
	if err != nil {
		return Dump{}, err
	}
	d, err := q.GetDBDump(ctx, store.GetDBDumpParams{ID: id, AppID: app.ID})
	if store.IsNotFound(err) {
		return Dump{}, apperr.NotFound("dump not found")
	}
	if err != nil {
		return Dump{}, fmt.Errorf("read the dump: %w", err)
	}
	url := ""
	if d.State == "ready" {
		url = c.Objects.PresignGet(d.ObjectKey, downloadTTL)
	}
	return dumpView(&d, url), nil
}

func dumpView(d *store.AppDbDump, url string) Dump {
	return Dump{ID: d.ID, State: d.State, SizeBytes: d.SizeBytes, Error: d.Error, CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt, DownloadURL: url, FinishedAt: d.FinishedAt}
}
