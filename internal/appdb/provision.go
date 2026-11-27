package appdb

import (
	"context"
	"fmt"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
)

// reconcileDatabases creates, drops and re-points app databases on the
// running server. Each database is its own unit: one failure is recorded
// on that database and retried next pass.
func (c *Controller) reconcileDatabases(ctx context.Context, with With, srv *store.AppDbServer,
	create, drop []store.AppDatabase, repoint []store.ListAppDatabasesRow) {
	adm, err := c.connect(ctx, srv)
	if err != nil {
		c.Logger.WarnContext(ctx, "could not reach the app database server", "error", err.Error())
		return
	}
	defer adm.close(ctx)
	if err := adm.bootstrap(ctx); err != nil {
		c.Logger.WarnContext(ctx, "could not prepare the app database server", "error", err.Error())
		return
	}
	for i := range create {
		c.create(ctx, with, adm, srv, &create[i])
	}
	for i := range drop {
		c.drop(ctx, with, adm, &drop[i])
	}
	for i := range repoint {
		c.repoint(ctx, with, srv, &repoint[i].AppDatabase)
	}
}

func (c *Controller) recordError(ctx context.Context, with With, d *store.AppDatabase, what string, err error) {
	c.Logger.WarnContext(ctx, "app database "+what+" failed; retrying", "app_id", d.AppID.String(), "error", err.Error())
	_ = with(ctx, func(db DB) error {
		return store.New(db).SetAppDatabaseError(ctx, store.SetAppDatabaseErrorParams{AppID: d.AppID, LastError: truncate(what+": "+err.Error(), 1000)})
	})
}

func (c *Controller) password(d *store.AppDatabase) (string, error) {
	pw, err := c.Keyring.Open(int(d.PasswordKeyVersion), secrets.DatabasePasswordAAD(d.AppID), d.Password)
	if err != nil {
		return "", fmt.Errorf("decrypt the database password: %w", err)
	}
	return string(pw), nil
}

// create makes the role and database, then gives the app its
// DATABASE_URL (a deployment releases it without a rebuild).
func (c *Controller) create(ctx context.Context, with With, adm *admin, srv *store.AppDbServer, d *store.AppDatabase) {
	pw, err := c.password(d)
	if err != nil {
		c.recordError(ctx, with, d, "creation", err)
		return
	}
	verifier, err := scramVerifier(pw)
	if err == nil {
		err = adm.createDatabase(ctx, d.Name, verifier, d.ConnectionLimit)
	}
	if err != nil {
		c.recordError(ctx, with, d, "creation", err)
		return
	}
	dep, err := c.inTx(ctx, with, func(q *store.Queries) (*store.Deployment, error) {
		if _, readyErr := q.AppDatabaseReady(ctx, store.AppDatabaseReadyParams{AppID: d.AppID, ServerGeneration: &srv.Generation}); readyErr != nil {
			if store.IsNotFound(readyErr) {
				return nil, nil //nolint:nilnil // deleted meanwhile: nothing to release
			}
			return nil, fmt.Errorf("mark the database ready: %w", readyErr)
		}
		return c.Apps.SetManagedEnv(ctx, q, d.AppID, apps.DatabaseURLKey, DatabaseURL(d.Name, pw, srv.Address, srv.Port), d.CreatedBy)
	})
	if err != nil {
		c.recordError(ctx, with, d, "creation", err)
		return
	}
	c.release(ctx, dep)
	c.m.created.Inc()
	c.Logger.InfoContext(ctx, "app database created", "app_id", d.AppID.String(), "database", d.Name)
}

// drop removes the database and role, then the app's DATABASE_URL.
func (c *Controller) drop(ctx context.Context, with With, adm *admin, d *store.AppDatabase) {
	if err := adm.dropDatabase(ctx, d.Name); err != nil {
		c.recordError(ctx, with, d, "deletion", err)
		return
	}
	dep, err := c.inTx(ctx, with, func(q *store.Queries) (*store.Deployment, error) {
		dep, err := c.Apps.UnsetManagedEnv(ctx, q, d.AppID, apps.DatabaseURLKey, nil)
		if err != nil {
			return nil, err
		}
		if err := q.DeleteAppDatabase(ctx, d.AppID); err != nil {
			return nil, fmt.Errorf("delete the database record: %w", err)
		}
		return dep, nil
	})
	if err != nil {
		c.recordError(ctx, with, d, "deletion", err)
		return
	}
	c.release(ctx, dep)
	c.Logger.InfoContext(ctx, "app database dropped", "app_id", d.AppID.String(), "database", d.Name)
}

// repoint gives an app the current server's address after a failover.
func (c *Controller) repoint(ctx context.Context, with With, srv *store.AppDbServer, d *store.AppDatabase) {
	pw, err := c.password(d)
	if err != nil {
		c.recordError(ctx, with, d, "re-pointing", err)
		return
	}
	dep, err := c.inTx(ctx, with, func(q *store.Queries) (*store.Deployment, error) {
		dep, setErr := c.Apps.SetManagedEnv(ctx, q, d.AppID, apps.DatabaseURLKey, DatabaseURL(d.Name, pw, srv.Address, srv.Port), nil)
		if setErr != nil {
			return nil, setErr
		}
		if genErr := q.SetAppDatabaseGeneration(ctx, store.SetAppDatabaseGenerationParams{AppID: d.AppID, ServerGeneration: &srv.Generation}); genErr != nil {
			return nil, fmt.Errorf("record the server generation: %w", genErr)
		}
		return dep, nil
	})
	if err != nil {
		c.recordError(ctx, with, d, "re-pointing", err)
		return
	}
	c.release(ctx, dep)
	c.Logger.InfoContext(ctx, "app re-pointed to the restored database server", "app_id", d.AppID.String(),
		"generation", srv.Generation, "address", srv.Address)
}

// inTx runs fn in a transaction on the lock connection.
func (c *Controller) inTx(ctx context.Context, with With, fn func(*store.Queries) (*store.Deployment, error)) (*store.Deployment, error) {
	var dep *store.Deployment
	err := with(ctx, func(db DB) error {
		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin: %w", err)
		}
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		if dep, err = fn(store.New(tx)); err != nil {
			return err
		}
		return tx.Commit(ctx)
	})
	return dep, err
}

func (c *Controller) release(ctx context.Context, dep *store.Deployment) {
	if dep != nil {
		c.Apps.Release(ctx, dep.ID)
	}
}

// monitor records the server's archiving state and database sizes; an
// archiving failure since the last look is logged.
func (c *Controller) monitor(ctx context.Context, with With, srv *store.AppDbServer) {
	adm, err := c.connect(ctx, srv)
	if err != nil {
		c.Logger.WarnContext(ctx, "could not reach the app database server to monitor it", "error", err.Error())
		return
	}
	defer adm.close(ctx)
	arch, err := adm.archiver(ctx)
	if err != nil {
		c.Logger.WarnContext(ctx, "could not read the archiver state", "error", err.Error())
		return
	}
	dbs, err := adm.databases(ctx)
	if err != nil {
		c.Logger.WarnContext(ctx, "could not read database sizes", "error", err.Error())
		return
	}
	conns, err := adm.connections(ctx)
	if err != nil {
		c.Logger.WarnContext(ctx, "could not count connections", "error", err.Error())
		return
	}
	if arch.Failed > srv.ArchiveFailedCount {
		c.Logger.ErrorContext(ctx, "WAL archiving is failing: recent writes are not backed up", "failed_count", arch.Failed,
			"last_failed_wal", arch.LastFailed, "last_archived_wal", arch.LastArchived)
	}
	var total int64
	for _, d := range dbs {
		total += d.SizeBytes
	}
	_ = with(ctx, func(db DB) error {
		q := store.New(db)
		for _, d := range dbs {
			if err := q.SetAppDatabaseStats(ctx, store.SetAppDatabaseStatsParams{Name: d.Name, SizeBytes: d.SizeBytes, Connections: d.Connections}); err != nil {
				return err
			}
		}
		return q.SetDBServerMonitor(ctx, store.SetDBServerMonitorParams{
			ID: srv.ID, ArchivedCount: arch.Archived, LastArchivedWal: arch.LastArchived, LastArchivedAt: arch.LastArchivedAt,
			ArchiveFailedCount: arch.Failed, LastFailedWal: arch.LastFailed, LastFailedAt: arch.LastFailedAt,
			DatabasesSizeBytes: total, Connections: conns,
		})
	})
}

// deleteDumps removes expired dump objects and their records.
func (c *Controller) deleteDumps(ctx context.Context, with With, dumps []store.AppDbDump) {
	for i := range dumps {
		d := &dumps[i]
		if err := c.Objects.Delete(ctx, d.ObjectKey); err != nil {
			c.Logger.WarnContext(ctx, "could not delete an expired dump; retrying", "dump", d.ID.String(), "error", err.Error())
			continue
		}
		_ = with(ctx, func(db DB) error { return store.New(db).DeleteDBDump(ctx, d.ID) })
	}
}
