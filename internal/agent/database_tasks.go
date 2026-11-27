package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Timeouts of the database server's long-running tasks.
const (
	dbBackupTimeout = 12 * time.Hour
	dbDumpTimeout   = 6 * time.Hour
	dbUploadTimeout = 6 * time.Hour
)

// setup resolves the server's addresses and prepares the dump directory.
// A node that cannot host the server says why in unavailable.
func (d *databases) setup(ctx context.Context, cfg *Config, advertise, publish netip.Addr) {
	d.publish, d.addr = publish, advertise
	if cfg.Database.PublishAddr != "" {
		d.publish = netip.MustParseAddr(cfg.Database.PublishAddr).Unmap() // validated
	}
	switch cfg.Database.Addr {
	case "":
	case hostGateway:
		gw, err := d.hostGateway(ctx, cfg.FirewallImage)
		if err != nil {
			d.unavailable = "could not resolve NOOK_AGENT_DB_ADDR=host-gateway: " + err.Error()
			return
		}
		d.addr = gw
	default:
		d.addr = netip.MustParseAddr(cfg.Database.Addr).Unmap() // validated
	}
	switch {
	case d.addr.IsLoopback() || d.addr.IsUnspecified():
		d.unavailable = "app containers cannot reach the database at " + d.addr.String() +
			"; set NOOK_AGENT_DB_ADDR to an address they can (the node's private address)"
	case !privateAdvertise(d.addr) && !cfg.AllowPublicAdvertise:
		d.unavailable = "NOOK_AGENT_DB_ADDR " + d.addr.String() + " is public; app databases are served only on private addresses"
	}
	_ = os.RemoveAll(d.dumpDir) // dumps do not survive a restart: the control plane fails them
	if err := os.MkdirAll(d.dumpDir, 0o700); err != nil {
		d.unavailable = "cannot create the dump directory: " + err.Error()
	}
}

// hostGateway resolves Docker's host gateway the way containers see it.
func (d *databases) hostGateway(ctx context.Context, image string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, firewallTimeout)
	defer cancel()
	if err := d.docker.ensureImage(ctx, image); err != nil {
		return netip.Addr{}, err
	}
	code, out, err := d.docker.runOnce(ctx, client.ContainerCreateOptions{
		Config: &container.Config{Image: image, Entrypoint: []string{"/bin/sh", "-c", "cat /etc/hosts"}, Labels: map[string]string{ManagedLabel: "true"}},
		HostConfig: &container.HostConfig{
			ExtraHosts: []string{"nook-host-gateway:host-gateway"}, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}, ReadonlyRootfs: true, NetworkMode: "none",
		},
	})
	if err != nil {
		return netip.Addr{}, err
	}
	if code != 0 {
		return netip.Addr{}, fmt.Errorf("helper exited with code %d", code)
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == "nook-host-gateway" {
			if a, perr := netip.ParseAddr(f[0]); perr == nil && a.Is4() {
				return a, nil
			}
		}
	}
	return netip.Addr{}, errors.New("the Docker engine reported no IPv4 host gateway")
}

func (d *databases) ensureNetwork(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	if _, err := d.docker.client.NetworkInspect(ctx, d.netName, client.NetworkInspectOptions{}); err == nil {
		return nil
	}
	enableIPv6 := false
	_, err := d.docker.client.NetworkCreate(ctx, d.netName, client.NetworkCreateOptions{
		Driver: "bridge", EnableIPv6: &enableIPv6,
		Options: map[string]string{"com.docker.network.bridge.name": dbBridge(d.netName), "com.docker.network.bridge.enable_icc": "false"},
		Labels:  map[string]string{ManagedLabel: "true"},
	})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("create %s: %w", d.netName, err)
	}
	return nil
}

// backup takes a base backup and applies retention; reported later.
func (d *databases) backup(cmd *agentv1.BackupDatabaseCommand) error {
	id := cmd.GetServerId()
	if !buildIDPattern.MatchString(id) || cmd.GetRetainAfter() == nil {
		return errors.New("invalid backup command")
	}
	// Its own claim: a stop (a planned failover) does not wait for a
	// backup; stopping the server ends the backup, which reports failure.
	key := "backup:" + id
	ctx, ok := d.claim(key, "backup")
	if !ok {
		return errBusy
	}
	retain := cmd.GetRetainAfter().AsTime().UTC().Format(time.RFC3339)
	d.wg.Go(func() {
		defer d.release(key)
		res := &agentv1.DatabaseBackupFinished{ServerId: id}
		name, err := d.runBackup(ctx, id, retain)
		if err != nil {
			res.Message = truncateMessage(err.Error())
			d.logger.Error("base backup failed", "server", id, "error", err.Error())
		} else {
			res.Ok, res.BackupName = true, name
			d.logger.Info("base backup finished", "server", id, "backup", name)
		}
		d.outbox.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_DatabaseBackupFinished{DatabaseBackupFinished: res}})
	})
	return nil
}

func (d *databases) runBackup(ctx context.Context, id, retainAfter string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dbBackupTimeout)
	defer cancel()
	res, err := d.docker.exec(ctx, dbName(id), []string{"nook-db", "backup", retainAfter}, nil, nil)
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", fmt.Errorf("backup exited with code %d: %s", res.Code, lastLines(res.Stderr, 5))
	}
	var out strings.Builder
	res, err = d.docker.exec(ctx, dbName(id), []string{"wal-g", "backup-list", "--json"}, nil, &limitedWriter{w: &out, n: 4 << 20})
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", fmt.Errorf("listing backups exited with code %d: %s", res.Code, lastLines(res.Stderr, 5))
	}
	var list []struct {
		Name string    `json:"backup_name"`
		Time time.Time `json:"time"`
	}
	if err := json.Unmarshal([]byte(out.String()), &list); err != nil || len(list) == 0 {
		return "", errors.New("the backup list is empty or unreadable")
	}
	newest := list[0]
	for _, b := range list[1:] {
		if b.Time.After(newest.Time) {
			newest = b
		}
	}
	return newest.Name, nil
}

// dump writes a plain-SQL dump of one database into the dump directory.
func (d *databases) dump(cmd *agentv1.DumpDatabaseCommand) error {
	if !buildIDPattern.MatchString(cmd.GetDumpId()) || !buildIDPattern.MatchString(cmd.GetServerId()) ||
		!databasePattern.MatchString(cmd.GetDatabase()) || cmd.GetMaxBytes() <= 0 {
		return errors.New("invalid dump command")
	}
	ctx, ok := d.claim(cmd.GetDumpId(), "dump")
	if !ok {
		return errBusy
	}
	d.wg.Go(func() {
		defer d.release(cmd.GetDumpId())
		res := &agentv1.DatabaseDumpFinished{DumpId: cmd.GetDumpId(), Stage: agentv1.DumpStage_DUMP_STAGE_DUMPED}
		size, sum, err := d.runDump(ctx, cmd)
		if err != nil {
			res.Message = truncateMessage(err.Error())
		} else {
			res.Ok, res.SizeBytes, res.Sha256 = true, size, sum
		}
		d.outbox.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_DatabaseDumpFinished{DatabaseDumpFinished: res}})
	})
	return nil
}

// dumpFile is a dump's file name in the dump directory (ids are validated
// UUIDs); files are opened through an os.Root confined to that directory.
func dumpFile(id string) string { return id + ".sql" }

func (d *databases) dumpRoot() (*os.Root, error) {
	root, err := os.OpenRoot(d.dumpDir)
	if err != nil {
		return nil, fmt.Errorf("open the dump directory: %w", err)
	}
	return root, nil
}

// removeDump deletes a dump's file, if any.
func (d *databases) removeDump(id string) {
	if root, err := d.dumpRoot(); err == nil {
		_ = root.Remove(dumpFile(id))
		_ = root.Close()
	}
}

func (d *databases) runDump(ctx context.Context, cmd *agentv1.DumpDatabaseCommand) (int64, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dbDumpTimeout)
	defer cancel()
	root, err := d.dumpRoot()
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(dumpFile(cmd.GetDumpId()), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, nil, fmt.Errorf("create the dump file: %w", err)
	}
	h := sha256.New()
	lw := &limitedWriter{w: io.MultiWriter(f, h), n: cmd.GetMaxBytes()}
	res, err := d.docker.exec(ctx, dbName(cmd.GetServerId()), []string{"nook-db", "dump", cmd.GetDatabase()}, nil, lw)
	closeErr := f.Close()
	switch {
	case lw.exceeded:
		err = fmt.Errorf("the dump is larger than %d bytes", cmd.GetMaxBytes())
	case err == nil && res.Code != 0:
		err = fmt.Errorf("pg_dump exited with code %d: %s", res.Code, lastLines(res.Stderr, 5))
	case err == nil && closeErr != nil:
		err = closeErr
	}
	if err != nil {
		_ = root.Remove(dumpFile(cmd.GetDumpId()))
		return 0, nil, err
	}
	return lw.written, h.Sum(nil), nil
}

// upload sends a finished dump to its presigned URL and deletes the file.
func (d *databases) upload(cmd *agentv1.UploadDumpCommand) error {
	u, err := url.Parse(cmd.GetUrl())
	if !buildIDPattern.MatchString(cmd.GetDumpId()) || err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("invalid upload command")
	}
	ctx, ok := d.claim(cmd.GetDumpId(), "upload")
	if !ok {
		return errBusy
	}
	d.wg.Go(func() {
		defer d.release(cmd.GetDumpId())
		res := &agentv1.DatabaseDumpFinished{DumpId: cmd.GetDumpId(), Stage: agentv1.DumpStage_DUMP_STAGE_UPLOADED}
		if err := d.runUpload(ctx, cmd); err != nil {
			res.Message = truncateMessage(err.Error())
		} else {
			res.Ok = true
		}
		d.removeDump(cmd.GetDumpId())
		d.outbox.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_DatabaseDumpFinished{DatabaseDumpFinished: res}})
	})
	return nil
}

func (d *databases) runUpload(ctx context.Context, cmd *agentv1.UploadDumpCommand) error {
	ctx, cancel := context.WithTimeout(ctx, dbUploadTimeout)
	defer cancel()
	root, err := d.dumpRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(dumpFile(cmd.GetDumpId()))
	if err != nil {
		return errors.New("the dump file is gone (the agent restarted?)")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat the dump file: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, cmd.GetUrl(), f)
	if err != nil {
		return errors.New("invalid upload URL")
	}
	req.ContentLength = st.Size()
	for k, v := range cmd.GetHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		// The URL is a credential: never in messages.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("upload the dump: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the storage service refused the dump: HTTP %d", resp.StatusCode)
	}
	return nil
}

// updateTLS replaces the running server's certificate and reloads it.
func (d *databases) updateTLS(ctx context.Context, cmd *agentv1.UpdateDatabaseTLSCommand) error {
	if !buildIDPattern.MatchString(cmd.GetServerId()) || cmd.GetCertificatePem() == "" || cmd.GetPrivateKeyPem() == "" {
		return errors.New("invalid TLS update")
	}
	in := strings.NewReader(cmd.GetCertificatePem() + "\n" + cmd.GetPrivateKeyPem() + "\n")
	res, err := d.docker.exec(ctx, dbName(cmd.GetServerId()), []string{"nook-db", "tls"}, in, nil)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("updating the certificate exited with code %d: %s", res.Code, lastLines(res.Stderr, 3))
	}
	return nil
}

// setEndpoint lets app containers reach the given server (none if the
// address is empty) and no other.
func (d *databases) setEndpoint(ctx context.Context, e *agentv1.DatabaseEndpoint) error {
	var ap netip.AddrPort
	if e.GetAddress() != "" {
		addr, err := netip.ParseAddr(e.GetAddress())
		if err != nil || e.GetPort() < 1 || e.GetPort() > 65535 {
			return errors.New("invalid database endpoint")
		}
		ap = netip.AddrPortFrom(addr.Unmap(), uint16(e.GetPort())) //nolint:gosec // G115: checked above.
	}
	if d.fw == nil || !d.fw.setDatabaseEndpoint(ap) {
		return nil
	}
	return d.fw.apply(ctx)
}

// limitedWriter fails once more than n bytes were written.
type limitedWriter struct {
	w        io.Writer
	n        int64
	written  int64
	exceeded bool
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.written+int64(len(p)) > l.n {
		l.exceeded = true
		return 0, errors.New("output limit exceeded")
	}
	n, err := l.w.Write(p)
	l.written += int64(n)
	return n, err
}

// lastLines returns the last n lines of s.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
