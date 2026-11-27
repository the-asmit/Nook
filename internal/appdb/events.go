package appdb

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// uploadURLTTL bounds a dump upload URL.
const uploadURLTTL = 30 * time.Minute

// serverOn returns the server a report from nodeID is about, if it was
// placed on that node.
func (c *Controller) serverOn(ctx context.Context, nodeID uuid.UUID, rawID string) (store.AppDbServer, bool, error) {
	id, ok := parseID(rawID)
	if !ok {
		return store.AppDbServer{}, false, nil
	}
	srv, err := c.Store.GetDBServer(ctx, id)
	if store.IsNotFound(err) {
		return store.AppDbServer{}, false, nil
	}
	if err != nil {
		return store.AppDbServer{}, false, fmt.Errorf("read the database server: %w", err)
	}
	return srv, srv.NodeID != nil && *srv.NodeID == nodeID, nil
}

// DatabaseStatus records a state change an agent reported for the server
// on its node. Every change is a compare-and-set: a report about a server
// that moved on (fenced, replaced) changes nothing, except that a
// replaced server reported running is told to stop.
func (c *Controller) DatabaseStatus(ctx context.Context, nodeID uuid.UUID, m *agentv1.DatabaseStatus) error {
	srv, ours, err := c.serverOn(ctx, nodeID, m.GetServerId())
	if err != nil || !ours {
		return err
	}
	switch m.GetState() {
	case agentv1.DatabaseState_DATABASE_STATE_RUNNING:
		return c.running(ctx, &srv, m)
	case agentv1.DatabaseState_DATABASE_STATE_FAILED:
		return c.failed(ctx, &srv, truncate(m.GetMessage(), 900))
	case agentv1.DatabaseState_DATABASE_STATE_STOPPED:
		switch srv.State {
		case store.AppDbServerStateStopping:
			if _, err := c.Store.DBServerStopped(ctx, store.DBServerStoppedParams{ID: srv.ID, FinalWal: truncate(m.GetFinalWal(), 64)}); err != nil && !store.IsNotFound(err) {
				return fmt.Errorf("record the stop: %w", err)
			}
			c.Logger.InfoContext(ctx, "app database server stopped cleanly for a planned failover", "server", srv.ID.String(), "final_wal", m.GetFinalWal())
		case store.AppDbServerStateFenced, store.AppDbServerStateFailed:
			if err := c.Store.DBServerContainerStopped(ctx, srv.ID); err != nil {
				return fmt.Errorf("record the stop: %w", err)
			}
		default:
		}
	default:
	}
	return nil
}

func (c *Controller) running(ctx context.Context, srv *store.AppDbServer, m *agentv1.DatabaseStatus) error {
	addr, ok := parseAddr(m.GetAddress())
	if !ok || m.GetPort() < 1 || m.GetPort() > 65535 {
		return nil
	}
	s, err := c.Store.DBServerRunning(ctx, store.DBServerRunningParams{ID: srv.ID, Address: addr.Unmap().String(), Port: m.GetPort()})
	if store.IsNotFound(err) {
		if srv.State == store.AppDbServerStateFenced || srv.State == store.AppDbServerStateFailed || srv.State == store.AppDbServerStateRemoved {
			// A replaced server runs again (its agent restarted it): fence.
			go c.sendStop(context.WithoutCancel(ctx), srv, false, srv.State == store.AppDbServerStateRemoved)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("record the server running: %w", err)
	}
	took := s.RunningAt.Sub(s.CauseAt)
	if s.Cause != "first" {
		c.m.failover.WithLabelValues(s.Cause).Observe(took.Seconds())
	}
	c.Logger.InfoContext(ctx, "app database server running", "server", s.ID.String(), "generation", s.Generation,
		"node", s.NodeName, "address", s.Address, "port", s.Port, "cause", s.Cause, "since_cause", took.Round(time.Millisecond).String())
	return nil
}

func (c *Controller) failed(ctx context.Context, srv *store.AppDbServer, msg string) error {
	switch srv.State {
	case store.AppDbServerStateRunning:
		// The container exited on a live node: start it again on its
		// volume (the leader sends the start).
		if _, err := c.Store.DBServerRestarting(ctx, store.DBServerRestartingParams{ID: srv.ID, LastError: msg}); err != nil && !store.IsNotFound(err) {
			return fmt.Errorf("record the exit: %w", err)
		}
		c.Logger.ErrorContext(ctx, "app database server exited; restarting it", "server", srv.ID.String(), "reason", msg)
	case store.AppDbServerStateStarting:
		if _, err := c.Store.DBServerFailed(ctx, store.DBServerFailedParams{ID: srv.ID, LastError: msg}); err != nil && !store.IsNotFound(err) {
			return fmt.Errorf("record the failure: %w", err)
		}
		c.Logger.ErrorContext(ctx, "app database server failed to start; the next attempt restores it", "server", srv.ID.String(), "reason", msg)
	case store.AppDbServerStateStopping:
		if err := c.Store.SetDBServerError(ctx, store.SetDBServerErrorParams{ID: srv.ID, LastError: "planned stop: " + msg}); err != nil {
			return fmt.Errorf("record the failure: %w", err)
		}
		c.Logger.ErrorContext(ctx, "planned stop of the app database server failed; retrying", "server", srv.ID.String(), "reason", msg)
	default:
	}
	return nil
}

// DatabaseBackupFinished records a base backup's outcome.
func (c *Controller) DatabaseBackupFinished(ctx context.Context, nodeID uuid.UUID, m *agentv1.DatabaseBackupFinished) error {
	srv, ours, err := c.serverOn(ctx, nodeID, m.GetServerId())
	if err != nil || !ours {
		return err
	}
	msg := truncate(m.GetMessage(), 1000)
	if err := c.Store.DBServerBackupFinished(ctx, store.DBServerBackupFinishedParams{
		ID: srv.ID, Ok: m.GetOk(), BackupName: truncate(m.GetBackupName(), 128), BackupError: msg,
	}); err != nil {
		return fmt.Errorf("record the backup: %w", err)
	}
	if m.GetOk() {
		c.m.backups.WithLabelValues("ok").Inc()
		c.Logger.InfoContext(ctx, "base backup finished", "server", srv.ID.String(), "backup", m.GetBackupName())
	} else {
		c.m.backups.WithLabelValues("error").Inc()
		c.Logger.ErrorContext(ctx, "base backup failed", "server", srv.ID.String(), "error", msg)
	}
	return nil
}

// DatabaseDumpFinished records a dump step and starts the upload once the
// dump is on the node.
func (c *Controller) DatabaseDumpFinished(ctx context.Context, nodeID uuid.UUID, m *agentv1.DatabaseDumpFinished) error {
	id, ok := parseID(m.GetDumpId())
	if !ok {
		return nil // not a dump of ours
	}
	if !m.GetOk() {
		return c.Store.DBDumpFailed(ctx, store.DBDumpFailedParams{ID: id, Error: truncate(m.GetMessage(), 1000)})
	}
	switch m.GetStage() {
	case agentv1.DumpStage_DUMP_STAGE_DUMPED:
		if len(m.GetSha256()) != 32 || m.GetSizeBytes() < 0 {
			return c.Store.DBDumpFailed(ctx, store.DBDumpFailedParams{ID: id, Error: "the node reported an invalid dump"})
		}
		d, err := c.Store.DBDumpDumped(ctx, store.DBDumpDumpedParams{ID: id, SizeBytes: m.GetSizeBytes(), Sha256: m.GetSha256()})
		if store.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("record the dump: %w", err)
		}
		// The upload command's result arrives through this agent's
		// stream, whose loop is running this handler.
		go c.sendUpload(context.WithoutCancel(ctx), &d, nodeID)
	case agentv1.DumpStage_DUMP_STAGE_UPLOADED:
		if _, err := c.Store.DBDumpReady(ctx, store.DBDumpReadyParams{ID: id, ExpiresAt: c.now().Add(c.cfg.DumpTTL)}); err != nil && !store.IsNotFound(err) {
			return fmt.Errorf("record the dump: %w", err)
		}
	default:
	}
	return nil
}

func (c *Controller) sendUpload(ctx context.Context, d *store.AppDbDump, nodeID uuid.UUID) {
	up := c.Objects.PresignPut(d.ObjectKey, d.SizeBytes, d.Sha256, uploadURLTTL)
	cmd := &agentv1.Command{Kind: &agentv1.Command_UploadDump{UploadDump: &agentv1.UploadDumpCommand{DumpId: d.ID.String(), Url: up.URL, Headers: up.Headers}}}
	res, err := c.Commander.Dispatch(ctx, nodeID, cmd, dispatchTimeout)
	if err == nil && res.GetError() != nil {
		err = errors.New(res.GetError().GetMessage())
	}
	if err != nil {
		_ = c.Store.DBDumpFailed(ctx, store.DBDumpFailedParams{ID: d.ID, Error: truncate("upload: "+err.Error(), 1000)})
	}
}

// AgentConnected reconciles the database server containers a (re)connected
// agent reports: replaced servers are stopped (fencing; their volumes stay
// until an admin removes them), removed ones deleted, and the current
// server is started again if its container stopped or vanished meanwhile.
func (c *Controller) AgentConnected(ctx context.Context, nodeID uuid.UUID, reports []*agentv1.DatabaseReport) {
	if !c.cfg.Enabled() {
		return
	}
	seen := map[uuid.UUID]*agentv1.DatabaseReport{}
	for _, r := range reports {
		srv, ours, err := c.serverOn(ctx, nodeID, r.GetServerId())
		if err != nil {
			c.Logger.WarnContext(ctx, "could not reconcile a database container", "error", err.Error())
			continue
		}
		if !ours {
			if id, perr := uuid.Parse(r.GetServerId()); perr == nil && r.GetRunning() {
				// Not a server placed on this node: never let it serve.
				_ = c.sendStop(ctx, &store.AppDbServer{ID: id, NodeID: &nodeID}, false, false)
			}
			continue
		}
		seen[srv.ID] = r
		switch srv.State {
		case store.AppDbServerStateRunning:
			if !r.GetRunning() {
				_ = c.failed(ctx, &srv, "the server's container stopped while its agent was away")
			}
		case store.AppDbServerStateFenced, store.AppDbServerStateFailed:
			if r.GetRunning() {
				_ = c.sendStop(ctx, &srv, false, false)
			} else if err := c.Store.DBServerContainerStopped(ctx, srv.ID); err != nil {
				c.Logger.WarnContext(ctx, "could not record a stopped database container", "error", err.Error())
			}
		case store.AppDbServerStateRemoved:
			_ = c.sendStop(ctx, &srv, false, true)
		default:
		}
	}
	cur, err := c.Store.CurrentDBServer(ctx)
	if err != nil || cur.NodeID == nil || *cur.NodeID != nodeID {
		return
	}
	r := seen[cur.ID]
	if r == nil && cur.State == store.AppDbServerStateRunning {
		_ = c.failed(ctx, &cur, "the server's container is gone from its node")
	}
	// The agent restarted during a backup: release the claim so the next
	// backup is not held up until it goes stale.
	if cur.BackupStartedAt != nil && !r.GetBackupRunning() {
		if err := c.Store.DBServerBackupFinished(ctx, store.DBServerBackupFinishedParams{
			ID: cur.ID, Ok: false, BackupError: "the agent restarted during the backup",
		}); err != nil {
			c.Logger.WarnContext(ctx, "could not release the backup claim", "error", err.Error())
		}
	}
}

func parseID(s string) (uuid.UUID, bool) {
	id, err := uuid.Parse(s)
	return id, err == nil
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	return a, err == nil
}
