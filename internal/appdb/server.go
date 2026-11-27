package appdb

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
	"uuid"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// noNodeError means no node can host the server now.
type noNodeError struct{ reason string }

func (e noNodeError) Error() string { return e.reason }

// backupKeyPurpose names the backup encryption key derived from the
// master key.
const backupKeyPurpose = "appdb-backups/v1"

// createServer places and records the next generation of the server. The
// superuser password carries over from prev on a restore (the restored
// cluster keeps its roles); backups stay encrypted with prev's key.
func (c *Controller) createServer(ctx context.Context, db DB, prev *store.AppDbServer, mode, cause string, causeAt time.Time, prefer *uuid.UUID) (store.AppDbServer, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return store.AppDbServer{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := store.New(tx)
	var avoid *uuid.UUID
	if prev != nil {
		avoid = prev.NodeID
	}
	node, err := c.chooseNode(ctx, q, prefer, avoid)
	if err != nil {
		return store.AppDbServer{}, err
	}
	generation, backupVersion := int32(1), int32(c.Keyring.Active()) //nolint:gosec // G115: versions are at most 1e6.
	var password []byte
	if prev != nil {
		generation, backupVersion = prev.Generation+1, prev.BackupKeyVersion
	}
	if mode == "restore" && prev != nil {
		if password, err = c.Keyring.Open(int(prev.PasswordKeyVersion), secrets.DatabaseSuperuserAAD(prev.ID), prev.SuperuserPassword); err != nil {
			return store.AppDbServer{}, fmt.Errorf("decrypt the server's password: %w", err)
		}
	} else {
		pw, perr := newPassword()
		if perr != nil {
			return store.AppDbServer{}, perr
		}
		password = []byte(pw)
	}
	id := uuid.NewV7()
	sealed, version, err := c.Keyring.Seal(secrets.DatabaseSuperuserAAD(id), password)
	clear(password)
	if err != nil {
		return store.AppDbServer{}, err
	}
	srv, err := q.CreateDBServer(ctx, store.CreateDBServerParams{
		ID: id, Generation: generation, Mode: mode, Cause: cause, CauseAt: causeAt, NodeID: &node.ID, NodeName: node.Name,
		MemoryMb: c.cfg.MemoryMB, SuperuserPassword: sealed, PasswordKeyVersion: int32(version), BackupKeyVersion: backupVersion, //nolint:gosec // G115: versions are at most 1e6.
	})
	if err != nil {
		return store.AppDbServer{}, fmt.Errorf("record the server: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return store.AppDbServer{}, fmt.Errorf("commit: %w", err)
	}
	c.Logger.InfoContext(ctx, "placing the app database server", "server", srv.ID.String(), "generation", generation,
		"node", node.Name, "mode", mode, "cause", cause)
	return srv, nil
}

// candidate is a node that may host the server.
type candidate struct {
	ID        uuid.UUID
	Name      string
	FreeMB    int64
	Labeled   bool
	Preferred bool
}

// chooseNode picks the node for the server: prefer (a planned failover's
// target) if given, else nodes labeled NodeLabel=true, then the most free
// memory; avoid (the previous server's node) only if nothing else fits.
// Nodes need room for the server's memory and more free disk than
// MinFreeDiskPercent.
func (c *Controller) chooseNode(ctx context.Context, q *store.Queries, prefer, avoid *uuid.UUID) (candidate, error) {
	rows, err := q.LockDatabaseNodes(ctx)
	if err != nil {
		return candidate{}, fmt.Errorf("lock nodes: %w", err)
	}
	res, err := q.NodeReservations(ctx)
	if err != nil {
		return candidate{}, fmt.Errorf("read reservations: %w", err)
	}
	reserved := map[uuid.UUID]int64{}
	for _, r := range res {
		if r.NodeID != nil {
			reserved[*r.NodeID] = r.MemoryMb
		}
	}
	var fits, avoided []candidate
	for i := range rows {
		r := &rows[i]
		free := r.MemoryTotalBytes>>20 - c.NodeReservedMemoryMB - reserved[r.ID]
		if free < int64(c.cfg.MemoryMB) || !diskOK(r.DiskFreeBytes, r.DiskTotalBytes, c.cfg.MinFreeDiskPercent) {
			continue
		}
		var labels map[string]string
		_ = json.Unmarshal(r.Labels, &labels)
		cand := candidate{ID: r.ID, Name: r.Name, FreeMB: free, Labeled: labels[c.cfg.NodeLabel] == "true", Preferred: prefer != nil && *prefer == r.ID}
		if avoid != nil && *avoid == r.ID {
			avoided = append(avoided, cand)
			continue
		}
		fits = append(fits, cand)
	}
	if prefer != nil {
		if i := slices.IndexFunc(append(fits, avoided...), func(c candidate) bool { return c.Preferred }); i >= 0 {
			return append(fits, avoided...)[i], nil
		}
		return candidate{}, noNodeError{"the chosen node cannot host the database server (not ready, too little memory or disk, or no database address)"}
	}
	if len(fits) == 0 {
		fits = avoided
	}
	if len(fits) == 0 {
		return candidate{}, noNodeError{"no ready node has " + strconv.Itoa(int(c.cfg.MemoryMB)) + " MB of memory and enough disk free for the database server"}
	}
	return slices.MinFunc(fits, func(a, b candidate) int {
		if a.Labeled != b.Labeled {
			if a.Labeled {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(b.FreeMB, a.FreeMB), cmp.Compare(a.Name, b.Name))
	}), nil
}

// diskOK reports whether at least minPercent of the disk is free (an
// unknown size passes: the node has not reported yet).
func diskOK(free *int64, total int64, minPercent int) bool {
	if free == nil || total <= 0 {
		return true
	}
	return *free*100 >= total*int64(minPercent)
}

// sendStart asks the server's node to start (or restore) it.
func (c *Controller) sendStart(ctx context.Context, with With, srv *store.AppDbServer) {
	cmd, expires, err := c.startCommand(ctx, srv)
	if err == nil {
		var res *agentv1.CommandResult
		res, err = c.Commander.Dispatch(ctx, *srv.NodeID, cmd, dispatchTimeout)
		if err == nil && res.GetError() != nil {
			err = errors.New(res.GetError().GetMessage())
		}
	}
	_ = with(ctx, func(db DB) error {
		q := store.New(db)
		if err != nil {
			return q.SetDBServerError(ctx, store.SetDBServerErrorParams{ID: srv.ID, LastError: truncate("could not start: "+err.Error(), 1000)})
		}
		return q.DBServerStartSent(ctx, store.DBServerStartSentParams{ID: srv.ID, TlsExpiresAt: &expires})
	})
	if err != nil {
		c.Logger.WarnContext(ctx, "could not start the app database server; retrying", "server", srv.ID.String(), "node", srv.NodeName, "error", err.Error())
	}
}

// startCommand builds the server's start command. Its environment holds
// secrets (superuser password, key, credentials): never logged.
func (c *Controller) startCommand(ctx context.Context, srv *store.AppDbServer) (*agentv1.Command, time.Time, error) {
	if srv.NodeID == nil {
		return nil, time.Time{}, errors.New("the server's node was removed")
	}
	node, err := c.Store.GetNodeDBInfo(ctx, *srv.NodeID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read the node: %w", err)
	}
	if node.DbAddress == "" || node.DbUnavailableReason != "" {
		return nil, time.Time{}, fmt.Errorf("node %s cannot host the database server: %s", node.Name, node.DbUnavailableReason)
	}
	certPEM, keyPEM, expires, err := c.serverCertificate(srv, node.DbAddress, node.DbPublishAddress)
	if err != nil {
		return nil, time.Time{}, err
	}
	pw, err := c.Keyring.Open(int(srv.PasswordKeyVersion), secrets.DatabaseSuperuserAAD(srv.ID), srv.SuperuserPassword)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("decrypt the server's password: %w", err)
	}
	key, err := c.Keyring.Derive(int(srv.BackupKeyVersion), backupKeyPurpose, 32)
	if err != nil {
		return nil, time.Time{}, err
	}
	mode := srv.Mode
	if srv.RunningAt != nil {
		mode = "existing" // a restart on its own volume
	}
	sharedBuffers := max(int(srv.MemoryMb)/4, 32)
	env := []*agentv1.EnvVar{
		{Name: "NOOK_DB_SUPERUSER", Value: Superuser},
		{Name: "NOOK_DB_SUPERUSER_PASSWORD", Value: string(pw)},
		{Name: "NOOK_DB_TLS_CERT", Value: certPEM},
		{Name: "NOOK_DB_TLS_KEY", Value: keyPEM},
		{Name: "NOOK_DB_ARCHIVE_TIMEOUT", Value: strconv.Itoa(int(c.cfg.ArchiveTimeout.Seconds()))},
		{Name: "NOOK_DB_MAX_CONNECTIONS", Value: strconv.Itoa(int(c.cfg.MaxConnections))},
		{Name: "NOOK_DB_SHARED_BUFFERS_MB", Value: strconv.Itoa(sharedBuffers)},
		{Name: "WALG_S3_PREFIX", Value: c.cfg.walgPrefix()},
		{Name: "AWS_ENDPOINT", Value: c.cfg.S3Endpoint},
		{Name: "AWS_REGION", Value: c.cfg.S3Region},
		{Name: "AWS_S3_FORCE_PATH_STYLE", Value: "true"},
		{Name: "AWS_ACCESS_KEY_ID", Value: c.cfg.S3AccessKeyID},
		{Name: "AWS_SECRET_ACCESS_KEY", Value: c.cfg.S3SecretAccessKey.Reveal()},
		{Name: "WALG_LIBSODIUM_KEY", Value: hex.EncodeToString(key)},
		{Name: "WALG_LIBSODIUM_KEY_TRANSFORM", Value: "hex"},
		// A replaced server that still runs somewhere must never
		// overwrite archived WAL.
		{Name: "WALG_PREVENT_WAL_OVERWRITE", Value: "true"},
	}
	clear(pw)
	clear(key)
	return &agentv1.Command{Kind: &agentv1.Command_StartDatabase{StartDatabase: &agentv1.StartDatabaseCommand{
		ServerId: srv.ID.String(), Image: c.cfg.Image, Mode: mode,
		MemoryBytes: int64(srv.MemoryMb) << 20, CpuMillicores: int64(c.cfg.CPUMillicores), Env: env,
	}}}, expires, nil
}

// serverCertificate issues the server's certificate for the addresses it
// is reached at (by apps, on its node, and by the control plane).
func (c *Controller) serverCertificate(_ *store.AppDbServer, addrs ...string) (certPEM, keyPEM string, expires time.Time, err error) {
	names := []string{}
	for _, a := range append(addrs, c.cfg.AdminHost) {
		if a != "" && validAddr(a) && !slices.Contains(names, a) {
			names = append(names, a)
		}
	}
	cert, err := c.CA.IssueServerCertificate(names, tlsTTL)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("issue the server certificate: %w", err)
	}
	var chain []byte
	for _, der := range cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("encode the server key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("parse the server certificate: %w", err)
	}
	return string(chain), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), leaf.NotAfter, nil
}

// renewTLS replaces the running server's certificate before it expires.
func (c *Controller) renewTLS(ctx context.Context, with With, srv *store.AppDbServer) {
	node, err := c.Store.GetNodeDBInfo(ctx, *srv.NodeID)
	if err != nil {
		return
	}
	certPEM, keyPEM, expires, err := c.serverCertificate(srv, node.DbAddress, node.DbPublishAddress)
	if err != nil {
		c.Logger.WarnContext(ctx, "could not issue a certificate for the database server", "error", err.Error())
		return
	}
	cmd := &agentv1.Command{Kind: &agentv1.Command_UpdateDatabaseTls{UpdateDatabaseTls: &agentv1.UpdateDatabaseTLSCommand{
		ServerId: srv.ID.String(), CertificatePem: certPEM, PrivateKeyPem: keyPEM,
	}}}
	res, err := c.Commander.Dispatch(ctx, *srv.NodeID, cmd, dispatchTimeout)
	if err == nil && res.GetError() != nil {
		err = errors.New(res.GetError().GetMessage())
	}
	if err != nil {
		c.Logger.WarnContext(ctx, "could not renew the database server's certificate; retrying", "error", err.Error())
		return
	}
	_ = with(ctx, func(db DB) error {
		return store.New(db).SetDBServerTLS(ctx, store.SetDBServerTLSParams{ID: srv.ID, TlsExpiresAt: &expires})
	})
	c.Logger.InfoContext(ctx, "renewed the database server's certificate", "expires", expires.Format(time.RFC3339))
}

// sendStop asks a server's node to stop it: cleanly with a final archive
// (planned failover), or just stop (fencing a replaced server), or
// remove container and volume. It reports whether the agent accepted.
func (c *Controller) sendStop(ctx context.Context, srv *store.AppDbServer, finalArchive, remove bool) bool {
	if srv.NodeID == nil {
		return false
	}
	cmd := &agentv1.Command{Kind: &agentv1.Command_StopDatabase{StopDatabase: &agentv1.StopDatabaseCommand{
		ServerId: srv.ID.String(), FinalArchive: finalArchive, Remove: remove,
	}}}
	res, err := c.Commander.Dispatch(ctx, *srv.NodeID, cmd, dispatchTimeout)
	if err == nil && res.GetError() != nil {
		err = errors.New(res.GetError().GetMessage())
	}
	if err != nil {
		c.Logger.WarnContext(ctx, "could not ask a node to stop a database server; retrying", "server", srv.ID.String(), "node", srv.NodeName, "error", err.Error())
		return false
	}
	return true
}

// sendBackup starts a base backup; a failure to hand it over releases the
// claim.
func (c *Controller) sendBackup(ctx context.Context, with With, srv *store.AppDbServer) {
	cmd := &agentv1.Command{Kind: &agentv1.Command_BackupDatabase{BackupDatabase: &agentv1.BackupDatabaseCommand{
		ServerId: srv.ID.String(), RetainAfter: timestamppb.New(c.now().Add(-c.cfg.Retention)),
	}}}
	res, err := c.Commander.Dispatch(ctx, *srv.NodeID, cmd, dispatchTimeout)
	if err == nil && res.GetError() != nil {
		err = errors.New(res.GetError().GetMessage())
	}
	if err == nil {
		c.Logger.InfoContext(ctx, "base backup started", "server", srv.ID.String())
		return
	}
	c.Logger.WarnContext(ctx, "could not start a base backup; retrying", "error", err.Error())
	_ = with(ctx, func(db DB) error {
		return store.New(db).DBServerBackupFinished(ctx, store.DBServerBackupFinishedParams{ID: srv.ID, Ok: false, BackupError: truncate(err.Error(), 1000)})
	})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
