package appdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Timeouts of the control plane's connections to the server.
const (
	adminConnectTimeout = 10 * time.Second
	adminQueryTimeout   = 60 * time.Second
)

// admin is a connection to the server as the superuser, over TLS verified
// against Nook's CA.
type admin struct {
	conn *pgx.Conn
}

func connectAdmin(ctx context.Context, host string, port int32, password string, roots *x509.CertPool) (*admin, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("database config: %w", err)
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database = host, uint16(port), Superuser, password, "postgres" //nolint:gosec // G115: a stored port.
	cfg.ConnectTimeout = adminConnectTimeout
	cfg.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host}
	cfg.Fallbacks = nil
	cfg.RuntimeParams["application_name"] = "nook-control-plane"
	ctx, cancel := context.WithTimeout(ctx, adminConnectTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		// pgx errors name host and user, never the password.
		return nil, fmt.Errorf("connect to the app database server at %s: %w", net.JoinHostPort(host, strconv.Itoa(int(port))), err)
	}
	return &admin{conn: conn}, nil
}

// close ends the connection, even after ctx ended.
func (a *admin) close(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), adminConnectTimeout)
	defer cancel()
	_ = a.conn.Close(ctx)
}

// exec runs one DDL statement (no parameters: DDL takes none).
func (a *admin) exec(ctx context.Context, sql string) error {
	ctx, cancel := context.WithTimeout(ctx, adminQueryTimeout)
	defer cancel()
	_, err := a.conn.Exec(ctx, sql)
	return err
}

// bootstrap keeps apps out of the server's own databases.
func (a *admin) bootstrap(ctx context.Context) error {
	if err := a.exec(ctx, `REVOKE CONNECT, TEMPORARY ON DATABASE postgres, template1 FROM PUBLIC`); err != nil {
		return fmt.Errorf("restrict the server's databases: %w", err)
	}
	return nil
}

// createDatabase creates (or completes) an app's role and database: the
// role logs in with verifier and may connect only to its own database;
// nobody else may connect to it (CONNECT revoked from PUBLIC). Safe to
// repeat.
func (a *admin) createDatabase(ctx context.Context, name, verifier string, limit int32) error {
	ident, err := sqlIdent(name)
	if err != nil {
		return err
	}
	pw, err := sqlLiteral(verifier)
	if err != nil {
		return err
	}
	var exists bool
	if err := a.conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, name).Scan(&exists); err != nil {
		return fmt.Errorf("look up role: %w", err)
	}
	role := "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT " +
		strconv.Itoa(int(limit)) + " PASSWORD " + pw
	stmt := "CREATE ROLE " + ident + " " + role
	if exists {
		stmt = "ALTER ROLE " + ident + " " + role
	}
	if err := a.exec(ctx, stmt); err != nil {
		return fmt.Errorf("create role: %w", err)
	}
	if err := a.conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, name).Scan(&exists); err != nil {
		return fmt.Errorf("look up database: %w", err)
	}
	if !exists {
		if err := a.exec(ctx, "CREATE DATABASE "+ident+" OWNER "+ident+" ENCODING 'UTF8' TEMPLATE template0"); err != nil {
			return fmt.Errorf("create database: %w", err)
		}
	}
	for _, stmt := range []string{
		"REVOKE ALL ON DATABASE " + ident + " FROM PUBLIC",
		"GRANT CONNECT, TEMPORARY, CREATE ON DATABASE " + ident + " TO " + ident,
		"ALTER DATABASE " + ident + " CONNECTION LIMIT " + strconv.Itoa(int(limit)),
	} {
		if err := a.exec(ctx, stmt); err != nil {
			return fmt.Errorf("restrict database: %w", err)
		}
	}
	return nil
}

// setPassword replaces the role's password; new connections need the new
// one at once (existing sessions continue until the app restarts).
func (a *admin) setPassword(ctx context.Context, name, verifier string) error {
	ident, err := sqlIdent(name)
	if err != nil {
		return err
	}
	pw, err := sqlLiteral(verifier)
	if err != nil {
		return err
	}
	if err := a.exec(ctx, "ALTER ROLE "+ident+" PASSWORD "+pw); err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	return nil
}

// dropDatabase removes an app's database (closing its connections) and
// role. Safe to repeat.
func (a *admin) dropDatabase(ctx context.Context, name string) error {
	ident, err := sqlIdent(name)
	if err != nil {
		return err
	}
	if err := a.exec(ctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)"); err != nil {
		return fmt.Errorf("drop database: %w", err)
	}
	if err := a.exec(ctx, "DROP ROLE IF EXISTS "+ident); err != nil {
		return fmt.Errorf("drop role: %w", err)
	}
	return nil
}

// archiver is the server's WAL archiving state (pg_stat_archiver).
type archiver struct {
	Archived       int64
	LastArchived   string
	LastArchivedAt *time.Time
	Failed         int64
	LastFailed     string
	LastFailedAt   *time.Time
}

func (a *admin) archiver(ctx context.Context) (archiver, error) {
	var s archiver
	err := a.conn.QueryRow(ctx, `SELECT archived_count, coalesce(last_archived_wal, ''), last_archived_time,
		failed_count, coalesce(last_failed_wal, ''), last_failed_time FROM pg_stat_archiver`).
		Scan(&s.Archived, &s.LastArchived, &s.LastArchivedAt, &s.Failed, &s.LastFailed, &s.LastFailedAt)
	if err != nil {
		return archiver{}, fmt.Errorf("read archiver state: %w", err)
	}
	return s, nil
}

// dbStats is one app database's size and connection count.
type dbStats struct {
	Name        string
	SizeBytes   int64
	Connections int32
}

func (a *admin) databases(ctx context.Context) ([]dbStats, error) {
	rows, err := a.conn.Query(ctx, `SELECT d.datname, pg_database_size(d.oid),
		(SELECT count(*) FROM pg_stat_activity s WHERE s.datid = d.oid)::int
		FROM pg_database d WHERE d.datname ~ '^app_[0-9a-f]{32}$' ORDER BY d.datname`)
	if err != nil {
		return nil, fmt.Errorf("read database sizes: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (dbStats, error) {
		var s dbStats
		err := r.Scan(&s.Name, &s.SizeBytes, &s.Connections)
		return s, err
	})
}

// connections counts client sessions.
func (a *admin) connections(ctx context.Context) (int32, error) {
	var n int32
	err := a.conn.QueryRow(ctx, `SELECT count(*)::int FROM pg_stat_activity WHERE backend_type = 'client backend'`).Scan(&n)
	return n, err
}
