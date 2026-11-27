package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type dbServerInfo struct {
	Node           string     `json:"node"`
	State          string     `json:"state"`
	Generation     int32      `json:"generation"`
	LastArchivedAt *time.Time `json:"last_archived_at"`
	LastArchived   string     `json:"last_archived_wal"`
	LastBackupAt   *time.Time `json:"last_backup_at"`
	ArchiveFailed  int64      `json:"archive_failures"`
}

type dbInfo struct {
	App             string        `json:"app"`
	Name            string        `json:"name"`
	State           string        `json:"state"`
	Available       bool          `json:"available"`
	SizeBytes       int64         `json:"size_bytes"`
	Connections     int32         `json:"connections"`
	ConnectionLimit int32         `json:"connection_limit"`
	LastError       string        `json:"last_error"`
	CreatedAt       time.Time     `json:"created_at"`
	PasswordRotated *time.Time    `json:"password_rotated_at"`
	Server          *dbServerInfo `json:"server"`
}

type dbDump struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	SizeBytes   int64  `json:"size_bytes"`
	Error       string `json:"error"`
	DownloadURL string `json:"download_url"`
}

func dbPath(ws, app string) string { return appPath(ws, app) + "/database" }

// pollEvery paces waiting for the server's progress.
const pollEvery = time.Second

func (r *runner) dbCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "db", Short: "Give an app a PostgreSQL database; inspect, rotate, dump or delete it"}
	cmd.AddCommand(r.dbCreateCommand(), r.dbInfoCommand(), r.dbRotateCommand(), r.dbDumpCommand(), r.dbDeleteCommand())
	return cmd
}

func (r *runner) dbCreateCommand() *cobra.Command {
	var noWait bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use: "create <app>", Short: "Create a database for the app (it gets DATABASE_URL and is redeployed)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var in dbInfo
			if doErr := c.do(cmd.Context(), http.MethodPost, dbPath(ws, args[0]), nil, &in); doErr != nil {
				return doErr
			}
			if !noWait {
				if in, err = r.waitDatabase(cmd.Context(), c, ws, args[0], timeout); err != nil {
					return err
				}
			}
			return r.emit(in, func() {
				if in.State == "ready" {
					r.printf("Database %s is ready. %s has DATABASE_URL (a secret, sslmode=require) and is being redeployed.\n", in.Name, in.App)
					return
				}
				r.printf("Database %s is being created; 'nook db info %s' shows when it is ready.\n", in.Name, in.App)
			})
		},
	}
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "return at once instead of waiting until the database is ready")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait (the first database also starts the server)")
	return cmd
}

// waitDatabase polls until the database is ready.
func (r *runner) waitDatabase(ctx context.Context, c *client, ws, app string, timeout time.Duration) (dbInfo, error) {
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		var in dbInfo
		if err := c.do(ctx, http.MethodGet, dbPath(ws, app), nil, &in); err != nil {
			return dbInfo{}, err
		}
		if in.State == "ready" {
			return in, nil
		}
		msg := "Creating the database"
		if in.Server == nil || in.Server.State != "running" {
			msg = "Starting the app database server"
		}
		if in.LastError != "" {
			msg += " (" + in.LastError + ")"
		}
		if msg != last {
			r.status("%s...", msg)
			last = msg
		}
		if time.Now().After(deadline) {
			return dbInfo{}, fmt.Errorf("the database is still %s after %s", in.State, timeout)
		}
		select {
		case <-ctx.Done():
			return dbInfo{}, ctx.Err()
		case <-time.After(pollEvery):
		}
	}
}

func (r *runner) dbInfoCommand() *cobra.Command {
	return &cobra.Command{
		Use: "info <app>", Short: "Show the app's database: size, connections, server, archiving and backups", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var in dbInfo
			if err := c.do(cmd.Context(), http.MethodGet, dbPath(ws, args[0]), nil, &in); err != nil {
				return err
			}
			return r.emit(in, func() { r.printDatabase(&in) })
		},
	}
}

func (r *runner) printDatabase(in *dbInfo) {
	state := in.State
	if in.State == "ready" && !in.Available {
		state = "unavailable (the database server is not running)"
	}
	r.printf("Database:     %s (%s)\n", in.Name, state)
	r.printf("Size:         %s\n", humanBytes(in.SizeBytes))
	r.printf("Connections:  %d of %d\n", in.Connections, in.ConnectionLimit)
	if in.Server != nil {
		r.printf("Server:       %s on node %s (generation %d)\n", in.Server.State, in.Server.Node, in.Server.Generation)
		r.printf("Last WAL:     %s\n", timeOr(in.Server.LastArchivedAt, "none archived yet", in.Server.LastArchived))
		r.printf("Last backup:  %s\n", timeOr(in.Server.LastBackupAt, "none yet", ""))
		if in.Server.ArchiveFailed > 0 {
			r.printf("Archiving:    %d failed attempts (see 'nook admin db status')\n", in.Server.ArchiveFailed)
		}
	}
	if in.PasswordRotated != nil {
		r.printf("Password:     rotated %s\n", in.PasswordRotated.Local().Format(time.RFC1123))
	}
	if in.LastError != "" {
		r.printf("Last error:   %s\n", in.LastError)
	}
}

func timeOr(t *time.Time, none, suffix string) string {
	if t == nil {
		return none
	}
	s := t.Local().Format(time.RFC1123) + " (" + time.Since(*t).Round(time.Second).String() + " ago)"
	if suffix != "" {
		s += ", " + suffix
	}
	return s
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func (r *runner) dbRotateCommand() *cobra.Command {
	return &cobra.Command{
		Use: "rotate-password <app>", Short: "Give the app's database role a new password (the app is redeployed)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var in dbInfo
			if err := c.do(cmd.Context(), http.MethodPost, dbPath(ws, args[0])+"/rotate-password", nil, &in); err != nil {
				return err
			}
			return r.emit(in, func() {
				r.printf("New password set for %s; the old one no longer works. %s is being redeployed with the new DATABASE_URL.\n", in.Name, in.App)
			})
		},
	}
}

func (r *runner) dbDumpCommand() *cobra.Command {
	var out string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use: "dump <app>", Short: "Export the app's database as SQL (to standard output or --file)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var d dbDump
			if doErr := c.do(cmd.Context(), http.MethodPost, dbPath(ws, args[0])+"/dumps", nil, &d); doErr != nil {
				return doErr
			}
			r.status("Dumping %s...", args[0])
			deadline := time.Now().Add(timeout)
			for d.State != "ready" {
				if d.State == "failed" {
					return fmt.Errorf("the dump failed: %s", d.Error)
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("the dump is still %s after %s", d.State, timeout)
				}
				select {
				case <-cmd.Context().Done():
					return cmd.Context().Err()
				case <-time.After(pollEvery):
				}
				if doErr := c.do(cmd.Context(), http.MethodGet, dbPath(ws, args[0])+"/dumps/"+url.PathEscape(d.ID), nil, &d); doErr != nil {
					return doErr
				}
			}
			n, err := r.download(cmd.Context(), c, d.DownloadURL, out)
			if err != nil {
				return err
			}
			if out != "" {
				r.status("Wrote %s (%s).", out, humanBytes(n))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "file", "f", "", "write the dump to this file (mode 0600) instead of standard output")
	cmd.Flags().DurationVar(&timeout, "timeout", time.Hour, "how long to wait for the dump")
	return cmd
}

// download copies the dump at u to path (or standard output).
func (r *runner) download(ctx context.Context, c *client, u, path string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return 0, errors.New("invalid download URL")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// The URL is a credential: never in messages.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("download the dump: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download the dump: HTTP %d", resp.StatusCode)
	}
	w := r.app.Stdout
	if path != "" {
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: the user names the output file.
		if createErr != nil {
			return 0, fmt.Errorf("create %s: %w", path, createErr)
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return n, fmt.Errorf("download the dump: %w", err)
	}
	return n, nil
}

func (r *runner) dbDeleteCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use: "delete <app> --yes", Short: "Drop the app's database and role (backups age out)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return &usageError{errors.New("deleting a database destroys its data: pass --yes to confirm")}
			}
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var in dbInfo
			if err := c.do(cmd.Context(), http.MethodDelete, dbPath(ws, args[0]), nil, &in); err != nil {
				return err
			}
			return r.emit(in, func() {
				r.printf("Database %s is being deleted; %s loses DATABASE_URL and is redeployed.\n", in.Name, in.App)
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm that the data is to be destroyed")
	return cmd
}

// Instance administrators: the server.

type dbServerStatus struct {
	ID              string     `json:"id"`
	Generation      int32      `json:"generation"`
	State           string     `json:"state"`
	Node            string     `json:"node"`
	Address         string     `json:"address"`
	Port            int32      `json:"port"`
	Cause           string     `json:"cause"`
	CauseAt         time.Time  `json:"cause_at"`
	RunningAt       *time.Time `json:"running_at"`
	LastError       string     `json:"last_error"`
	ArchivedCount   int64      `json:"archived_count"`
	LastArchived    string     `json:"last_archived_wal"`
	LastArchivedAt  *time.Time `json:"last_archived_at"`
	ArchiveFailures int64      `json:"archive_failures"`
	LastFailed      string     `json:"last_failed_wal"`
	LastFailedAt    *time.Time `json:"last_failed_at"`
	LastBackupAt    *time.Time `json:"last_backup_at"`
	LastBackup      string     `json:"last_backup"`
	BackupError     string     `json:"last_backup_error"`
	BackupRunning   bool       `json:"backup_running"`
	SizeBytes       int64      `json:"size_bytes"`
	Connections     int32      `json:"connections"`
	FinalWAL        string     `json:"final_wal"`
	ContainerStop   bool       `json:"container_stopped"`
}

type dbStatus struct {
	Enabled        bool             `json:"enabled"`
	Databases      int64            `json:"databases"`
	Storage        string           `json:"storage"`
	ArchiveTimeout string           `json:"archive_timeout"`
	BackupInterval string           `json:"backup_interval"`
	Retention      string           `json:"retention"`
	Current        *dbServerStatus  `json:"current"`
	Servers        []dbServerStatus `json:"servers"`
}

func (r *runner) adminDBCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "db", Short: "The app database server: status, planned failover, removing replaced servers"}
	status := &cobra.Command{
		Use: "status", Short: "Show the server, its archiving and backups, and its generations", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			var s dbStatus
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/admin/database", nil, &s); err != nil {
				return err
			}
			return r.emit(s, func() { r.printDBStatus(&s) })
		},
	}
	var to string
	var noWait bool
	var timeout time.Duration
	failover := &cobra.Command{
		Use: "failover --to <node>", Short: "Move the server to another node (clean stop, final archive, restore: no data lost)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if to == "" {
				return &usageError{errors.New("--to <node> is required")}
			}
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			start := time.Now()
			var s dbStatus
			if err := c.do(cmd.Context(), http.MethodPost, "/api/v1/admin/database/failover", map[string]string{"to": to}, &s); err != nil {
				return err
			}
			if noWait {
				return r.emit(s, func() { r.printf("The database server is moving to %s.\n", to) })
			}
			r.status("Stopping the server cleanly and archiving its last WAL...")
			deadline := time.Now().Add(timeout)
			for s.Current == nil || s.Current.Node != to || s.Current.State != "running" {
				if time.Now().After(deadline) {
					return fmt.Errorf("the server is not running on %s after %s (see 'nook admin db status')", to, timeout)
				}
				select {
				case <-cmd.Context().Done():
					return cmd.Context().Err()
				case <-time.After(pollEvery):
				}
				if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/admin/database", nil, &s); err != nil {
					return err
				}
			}
			took := time.Since(start).Round(100 * time.Millisecond)
			return r.emit(map[string]any{"status": s, "seconds": took.Seconds()}, func() {
				r.printf("The database server runs on %s (generation %d); it took %s. Apps are being re-pointed.\n", to, s.Current.Generation, took)
			})
		},
	}
	failover.Flags().StringVar(&to, "to", "", "the node to move the server to")
	failover.Flags().BoolVar(&noWait, "no-wait", false, "return once the move has started")
	failover.Flags().DurationVar(&timeout, "timeout", 30*time.Minute, "how long to wait for the server to run on the node")
	remove := &cobra.Command{
		Use: "remove <server-id>", Short: "Delete a replaced server's container and volume on its node", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			if err := c.do(cmd.Context(), http.MethodDelete, "/api/v1/admin/database/servers/"+url.PathEscape(args[0]), nil, nil); err != nil {
				return err
			}
			return r.emit(map[string]string{"removed": args[0]}, func() { r.printf("Removed server %s's container and volume.\n", args[0]) })
		},
	}
	cmd.AddCommand(status, failover, remove)
	return cmd
}

func (r *runner) printDBStatus(s *dbStatus) {
	if !s.Enabled {
		r.printf("App databases are not set up on this installation (NOOK_APPDB_IMAGE).\n")
		return
	}
	r.printf("Databases:    %d\n", s.Databases)
	r.printf("Backups:      %s (base backup every %s, kept %s; up to %s of writes can be lost in a crash)\n",
		s.Storage, s.BackupInterval, s.Retention, s.ArchiveTimeout)
	if cur := s.Current; cur != nil {
		r.printf("Server:       %s on %s at %s:%d (generation %d, %s)\n", cur.State, cur.Node, cur.Address, cur.Port, cur.Generation, cur.Cause)
		r.printf("Archiving:    %d segments, last %s\n", cur.ArchivedCount, timeOr(cur.LastArchivedAt, "none yet", cur.LastArchived))
		if cur.ArchiveFailures > 0 {
			r.printf("              %d FAILED attempts, last %s\n", cur.ArchiveFailures, timeOr(cur.LastFailedAt, "-", cur.LastFailed))
		}
		backup := timeOr(cur.LastBackupAt, "none yet", cur.LastBackup)
		if cur.BackupRunning {
			backup += " (one is running)"
		}
		r.printf("Last backup:  %s\n", backup)
		if cur.BackupError != "" {
			r.printf("Backup error: %s\n", cur.BackupError)
		}
		r.printf("Size:         %s, %d connections\n", humanBytes(cur.SizeBytes), cur.Connections)
		if cur.LastError != "" {
			r.printf("Last error:   %s\n", cur.LastError)
		}
	} else {
		r.printf("Server:       none running\n")
	}
	r.printf("\nGENERATION  STATE     NODE                 CAUSE     ID\n")
	for i := range s.Servers {
		g := &s.Servers[i]
		note := ""
		if g.State == "fenced" && !g.ContainerStop {
			note = " (container not yet stopped)"
		} else if g.State == "fenced" || g.State == "failed" {
			note = " (volume kept: nook admin db remove " + g.ID + ")"
		}
		r.printf("%-11d %-9s %-20s %-9s %s%s\n", g.Generation, g.State, g.Node, g.Cause, g.ID, note)
	}
}

// nodeLabelCommand is `nook node label`: set (key=value) or remove (key-)
// labels.
func (r *runner) nodeLabelCommand() *cobra.Command {
	return &cobra.Command{
		Use: "label <name|id> key=value... | key-...", Short: "Set or remove node labels (nook.database=true prefers the node for the app database server)",
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			path := "/api/v1/nodes/" + url.PathEscape(args[0])
			var n nodeInfo
			if err := c.do(cmd.Context(), http.MethodGet, path, nil, &n); err != nil {
				return err
			}
			labels := n.Labels
			if labels == nil {
				labels = map[string]string{}
			}
			for _, a := range args[1:] {
				if k, ok := strings.CutSuffix(a, "-"); ok && !strings.Contains(a, "=") {
					delete(labels, k)
					continue
				}
				k, v, ok := strings.Cut(a, "=")
				if !ok || k == "" {
					return &usageError{fmt.Errorf("%q: use key=value to set or key- to remove", a)}
				}
				labels[k] = v
			}
			if err := c.do(cmd.Context(), http.MethodPut, path+"/labels", map[string]any{"labels": labels}, &n); err != nil {
				return err
			}
			return r.emit(n, func() { r.printf("Node %s labels: %v\n", n.Name, n.Labels) })
		},
	}
}
