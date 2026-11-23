package postgres

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// MigrationLockID is the key of the session-level advisory lock held while
// migrating. Every Nook instance uses the same key, so only one of them
// migrates at a time; the value spells "nookmigr" in ASCII.
const MigrationLockID int64 = 0x6e6f6f6b6d696772

// closeTimeout bounds closing the lock connection after migrating, which
// runs on a context detached from the (possibly expired) caller's.
const closeTimeout = 5 * time.Second

// Migrate applies every pending migration in fsys while holding
// MigrationLockID. Instances that start while another is migrating block
// on the lock (bounded by ctx), then find nothing left to apply.
//
// The lock is taken here, around the whole goose run, rather than through
// goose's SessionLocker hook: goose's Up first checks for pending
// migrations without the lock, and that check creates the version table,
// so two instances on an empty database could race on CREATE TABLE.
func Migrate(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS, logger *slog.Logger) error {
	unlock, err := acquireMigrationLock(ctx, pool, logger)
	if err != nil {
		return err
	}
	defer unlock()

	// goose speaks database/sql; this adapter borrows connections from the
	// pgx pool rather than opening a second, unbounded set. Closing it
	// does not close the pool.
	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()

	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithDisableGlobalRegistry(true),
		goose.WithSlog(logger),
	)
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	version, err := provider.GetDBVersion(ctx)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	logger.InfoContext(ctx, "database schema is up to date", "applied", len(results), "version", version)
	return nil
}

// acquireMigrationLock takes the advisory lock on a dedicated connection
// and returns a function that releases it by closing that connection.
//
// A dedicated connection (not one borrowed from the pool) is used because
// the lock belongs to the database session: if it were returned to the
// pool still holding the lock, an unrelated query would inherit it.
// Closing the session is the one release that cannot fail to happen;
// if the process dies, Postgres releases the lock when the socket drops.
func acquireMigrationLock(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) (func(), error) {
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return nil, fmt.Errorf("open migration lock connection: %w", err)
	}
	release := func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
		defer cancel()
		if err := conn.Close(closeCtx); err != nil {
			logger.WarnContext(ctx, "closing migration lock connection", "error", err.Error())
		}
	}

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", MigrationLockID).Scan(&acquired); err != nil {
		release()
		return nil, fmt.Errorf("try migration lock: %w", err)
	}
	if acquired {
		return release, nil
	}
	// Block rather than poll: Postgres wakes us the moment the holder
	// finishes, and ctx still bounds the wait.
	logger.InfoContext(ctx, "another instance is migrating the database; waiting for it to finish")
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", MigrationLockID); err != nil {
		release()
		return nil, fmt.Errorf("wait for migration lock: %w", err)
	}
	return release, nil
}
