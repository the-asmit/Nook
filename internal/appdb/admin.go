package appdb

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Status is the app database server as instance admins see it.
type Status struct {
	Enabled        bool           `json:"enabled"`
	Databases      int64          `json:"databases"`
	Storage        string         `json:"storage"`
	ArchiveTimeout string         `json:"archive_timeout"`
	BackupInterval string         `json:"backup_interval"`
	Retention      string         `json:"retention"`
	Current        *ServerStatus  `json:"current,omitempty"`
	Servers        []ServerStatus `json:"servers"`
}

// ServerStatus is one generation of the server.
type ServerStatus struct {
	ID               uuid.UUID  `json:"id"`
	Generation       int32      `json:"generation"`
	State            string     `json:"state"`
	Node             string     `json:"node"`
	Address          string     `json:"address,omitempty"`
	Port             int32      `json:"port,omitempty"`
	Mode             string     `json:"mode"`
	Cause            string     `json:"cause"`
	CauseAt          time.Time  `json:"cause_at"`
	RunningAt        *time.Time `json:"running_at,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
	ArchivedCount    int64      `json:"archived_count"`
	LastArchived     string     `json:"last_archived_wal,omitempty"`
	LastArchivedAt   *time.Time `json:"last_archived_at,omitempty"`
	ArchiveFailures  int64      `json:"archive_failures"`
	LastFailed       string     `json:"last_failed_wal,omitempty"`
	LastFailedAt     *time.Time `json:"last_failed_at,omitempty"`
	LastBackupAt     *time.Time `json:"last_backup_at,omitempty"`
	LastBackup       string     `json:"last_backup,omitempty"`
	BackupError      string     `json:"last_backup_error,omitempty"`
	BackupRunning    bool       `json:"backup_running"`
	SizeBytes        int64      `json:"size_bytes"`
	Connections      int32      `json:"connections"`
	CheckedAt        *time.Time `json:"checked_at,omitempty"`
	FinalWAL         string     `json:"final_wal,omitempty"`
	FencedAt         *time.Time `json:"fenced_at,omitempty"`
	ContainerStopped bool       `json:"container_stopped"`
	TLSExpiresAt     *time.Time `json:"tls_expires_at,omitempty"`
}

func serverStatus(s *store.AppDbServer) ServerStatus {
	return ServerStatus{
		ID: s.ID, Generation: s.Generation, State: string(s.State), Node: s.NodeName, Address: s.Address, Port: s.Port,
		Mode: s.Mode, Cause: s.Cause, CauseAt: s.CauseAt, RunningAt: s.RunningAt, LastError: s.LastError,
		ArchivedCount: s.ArchivedCount, LastArchived: s.LastArchivedWal, LastArchivedAt: s.LastArchivedAt,
		ArchiveFailures: s.ArchiveFailedCount, LastFailed: s.LastFailedWal, LastFailedAt: s.LastFailedAt,
		LastBackupAt: s.LastBackupAt, LastBackup: s.LastBackupName, BackupError: s.LastBackupError, BackupRunning: s.BackupStartedAt != nil,
		SizeBytes: s.DatabasesSizeBytes, Connections: s.Connections, CheckedAt: s.CheckedAt, FinalWAL: s.FinalWal,
		FencedAt: s.FencedAt, ContainerStopped: s.StoppedAt != nil, TLSExpiresAt: s.TlsExpiresAt,
	}
}

// Status reports the server and its recent generations (instance admins).
func (c *Controller) Status(ctx context.Context) (Status, error) {
	out := Status{
		Enabled: c.cfg.Enabled(), Servers: []ServerStatus{},
		ArchiveTimeout: c.cfg.ArchiveTimeout.String(), BackupInterval: c.cfg.BackupInterval.String(), Retention: c.cfg.Retention.String(),
	}
	if !out.Enabled {
		return out, nil
	}
	out.Storage = c.cfg.walgPrefix()
	n, err := c.Store.CountAppDatabases(ctx)
	if err != nil {
		return Status{}, fmt.Errorf("count databases: %w", err)
	}
	out.Databases = n
	servers, err := c.Store.ListDBServers(ctx, 20)
	if err != nil {
		return Status{}, fmt.Errorf("list servers: %w", err)
	}
	for i := range servers {
		s := serverStatus(&servers[i])
		out.Servers = append(out.Servers, s)
		switch servers[i].State {
		case store.AppDbServerStateStarting, store.AppDbServerStateRunning, store.AppDbServerStateStopping:
			out.Current = &s
		default:
		}
	}
	return out, nil
}

// Failover moves the server to another node on purpose: it is shut down
// cleanly, the WAL it has not archived yet is pushed, and the leader
// restores it on the target from the backups, losing nothing. Apps cannot
// reach their databases meanwhile (instance admins).
func (c *Controller) Failover(ctx context.Context, actor workspace.Actor, toNode string) (Status, error) {
	if !c.cfg.Enabled() {
		return Status{}, errNotConfigured
	}
	var srv store.AppDbServer
	err := c.Store.InTx(ctx, func(q *store.Queries) error {
		cur, err := q.CurrentDBServer(ctx)
		if store.IsNotFound(err) {
			return apperr.Conflict("no_database_server", "there is no app database server")
		}
		if err != nil {
			return fmt.Errorf("read the server: %w", err)
		}
		if cur.State != store.AppDbServerStateRunning {
			return apperr.Conflict("database_server_busy", "the app database server is %s; wait until it runs", cur.State)
		}
		// The target restores from a base backup, and stopping the server
		// ends a backup that is still running: moving before the first one
		// has finished would leave nothing to restore.
		hasBackup, err := q.AnyDBServerBackup(ctx)
		if err != nil {
			return fmt.Errorf("check for a base backup: %w", err)
		}
		if !hasBackup {
			return apperr.Conflict("database_no_backup", "the app database server has no base backup yet to restore from; wait until `nook admin db status` shows one")
		}
		node, err := q.GetLiveNodeByName(ctx, toNode)
		if store.IsNotFound(err) {
			return apperr.NotFound("node not found")
		}
		if err != nil {
			return fmt.Errorf("read the node: %w", err)
		}
		if cur.NodeID != nil && *cur.NodeID == node.ID {
			return apperr.Invalid("same_node", "the server already runs on %s", node.Name)
		}
		if node.Status != store.NodeStatusReady || node.Draining || node.DbAddress == "" || node.DbUnavailableReason != "" {
			return apperr.Invalid("node_unsuitable", "node %s cannot host the database server (not ready, draining, or no database address)", node.Name)
		}
		if srv, err = q.DBServerStopping(ctx, store.DBServerStoppingParams{ID: cur.ID, MoveToNodeID: &node.ID}); err != nil {
			return fmt.Errorf("begin the failover: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionDatabaseFailover, TargetType: audit.TargetDBServer, TargetID: cur.ID.String(),
			Metadata: map[string]any{"from": cur.NodeName, "to": node.Name, "generation": cur.Generation},
		})
	})
	if err != nil {
		return Status{}, err
	}
	c.Logger.InfoContext(ctx, "planned failover of the app database server", "from", srv.NodeName, "to", toNode)
	// The leader sends it again until the agent accepts.
	if c.sendStop(ctx, &srv, true, false) {
		if err := c.Store.DBServerStopSent(ctx, srv.ID); err != nil {
			return Status{}, fmt.Errorf("record the stop: %w", err)
		}
	}
	return c.Status(ctx)
}

// RemoveServer deletes a replaced server's container and volume on its
// node (instance admins). The current server cannot be removed.
func (c *Controller) RemoveServer(ctx context.Context, actor workspace.Actor, id uuid.UUID) error {
	srv, err := c.Store.GetDBServer(ctx, id)
	if store.IsNotFound(err) {
		return apperr.NotFound("database server not found")
	}
	if err != nil {
		return fmt.Errorf("read the server: %w", err)
	}
	if srv.State != store.AppDbServerStateFenced && srv.State != store.AppDbServerStateFailed {
		return apperr.Conflict("database_server_in_use", "only replaced or failed servers can be removed (this one is %s)", srv.State)
	}
	if srv.NodeID != nil {
		cmd := &agentv1.Command{Kind: &agentv1.Command_StopDatabase{StopDatabase: &agentv1.StopDatabaseCommand{ServerId: srv.ID.String(), Remove: true}}}
		res, err := c.Commander.Dispatch(ctx, *srv.NodeID, cmd, dispatchTimeout)
		if err == nil && res.GetError() != nil {
			err = errors.New(res.GetError().GetMessage())
		}
		if err != nil {
			return apperr.Conflict("node_unreachable", "node %s could not remove the server's container and volume; try again when it is online", srv.NodeName)
		}
	}
	return c.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.MarkDBServerRemoved(ctx, srv.ID); err != nil && !store.IsNotFound(err) {
			return fmt.Errorf("mark the server removed: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionDatabaseRemoveServer, TargetType: audit.TargetDBServer, TargetID: srv.ID.String(),
			Metadata: map[string]any{"node": srv.NodeName, "generation": srv.Generation},
		})
	})
}
