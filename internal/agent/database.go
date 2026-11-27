package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// The app database server: one PostgreSQL container (image nook-postgres)
// per installation, on the node the control plane chose, with its data on
// a Docker volume. Its port is published on the node's database address,
// which app containers on every node may reach only while it is the
// current server's endpoint (see the egress firewall).

const (
	databaseLabel   = "nook.database"
	dbNamePrefix    = "nook-db-"
	dbContainerPort = 5432
	// dbStopGrace is how long PostgreSQL gets for a clean (fast) shutdown.
	dbStopGrace = 120
	// How long the server may take to accept connections: a restore
	// downloads a base backup and replays WAL.
	dbStartTimeout   = 10 * time.Minute
	dbRestoreTimeout = 6 * time.Hour
	dbReadyPoll      = time.Second
	dbTmpfsOptions   = "rw,noexec,nosuid,nodev,size=67108864"
	dbPIDsLimit      = 2048
	dbShmBytes       = 256 << 20
	dbLogLines       = 40
	// defaultDBNetwork is the default network of the server container.
	defaultDBNetwork = "nook-db"
	// hostGateway asks the agent to use Docker's host gateway address
	// (development: Docker Desktop's host.docker.internal).
	hostGateway = "host-gateway"
)

var (
	imageRefPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}(@sha256:[0-9a-f]{64})?$`)
	envNamePattern   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	databasePattern  = regexp.MustCompile(`^app_[0-9a-f]{32}$`)
	walSegmentRegexp = regexp.MustCompile(`^[0-9A-F]{24}$`)
)

func dbName(serverID string) string { return dbNamePrefix + serverID }

// dbBridge names the Linux bridge of the database network.
func dbBridge(name string) string {
	if name == defaultDBNetwork {
		return "nkdb0"
	}
	return "nkd" + buildBridge(name)[3:]
}

// databases runs the app database server containers of this node.
type databases struct {
	docker  *docker
	outbox  *outbox
	logger  *slog.Logger
	nodeID  func() string
	ready   func() error
	fw      *firewall // nil when the egress filter is off
	netName string
	addr    netip.Addr // where apps reach the server
	publish netip.Addr // where its port is bound
	port    int
	// unavailable says why this node cannot host the server ("" if it can).
	unavailable string
	dumpDir     string
	http        *http.Client

	mu       sync.Mutex
	ctx      context.Context
	busy     map[string]string
	stopping map[string]bool
	wg       sync.WaitGroup
}

func (d *databases) report(s *agentv1.DatabaseStatus) {
	d.outbox.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_DatabaseStatus{DatabaseStatus: s}})
}

// claim marks an operation on a server as running; false if one is.
func (d *databases) claim(id, op string) (context.Context, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx == nil || d.busy[id] != "" {
		return nil, false
	}
	d.busy[id] = op
	return d.ctx, true
}

func (d *databases) release(id string) {
	d.mu.Lock()
	delete(d.busy, id)
	d.mu.Unlock()
}

func validateStartDatabase(cmd *agentv1.StartDatabaseCommand) error {
	switch {
	case !buildIDPattern.MatchString(cmd.GetServerId()):
		return errors.New("invalid server id")
	case !imageRefPattern.MatchString(cmd.GetImage()):
		return errors.New("invalid image")
	case cmd.GetMode() != "init" && cmd.GetMode() != "restore" && cmd.GetMode() != "existing":
		return errors.New("invalid mode")
	case cmd.GetMemoryBytes() < 64<<20 || cmd.GetMemoryBytes() > maxAppMemory:
		return errors.New("invalid memory limit")
	case cmd.GetCpuMillicores() < 0 || cmd.GetCpuMillicores() > maxAppMillicore:
		return errors.New("invalid CPU limit")
	}
	for _, e := range cmd.GetEnv() {
		if !envNamePattern.MatchString(e.GetName()) || e.GetName() == "NOOK_DB_MODE" {
			return errors.New("invalid environment variable name")
		}
	}
	return nil
}

// start runs the server unless it runs; the outcome is reported later.
func (d *databases) start(cmd *agentv1.StartDatabaseCommand) error {
	if err := validateStartDatabase(cmd); err != nil {
		return err
	}
	if d.unavailable != "" {
		return errors.New(d.unavailable)
	}
	ctx, ok := d.claim(cmd.GetServerId(), "start")
	if !ok {
		return nil // already starting (or stopping): the control plane follows the reports
	}
	d.mu.Lock()
	delete(d.stopping, cmd.GetServerId())
	d.mu.Unlock()
	d.wg.Go(func() {
		defer d.release(cmd.GetServerId())
		d.run(ctx, cmd)
	})
	return nil
}

func (d *databases) run(ctx context.Context, cmd *agentv1.StartDatabaseCommand) {
	id := cmd.GetServerId()
	fail := func(msg string) {
		d.logger.Warn("app database server failed to start", "server", id, "reason", msg)
		d.report(&agentv1.DatabaseStatus{ServerId: id, State: agentv1.DatabaseState_DATABASE_STATE_FAILED, Message: msg})
	}
	d.report(&agentv1.DatabaseStatus{ServerId: id, State: agentv1.DatabaseState_DATABASE_STATE_STARTING})
	if err := d.ready(); err != nil {
		fail(err.Error())
		return
	}
	containerID, running := d.existing(ctx, id)
	if !running {
		var err error
		if containerID, err = d.create(ctx, cmd); err != nil {
			fail(err.Error())
			return
		}
	}
	timeout := dbStartTimeout
	if cmd.GetMode() == "restore" {
		timeout = dbRestoreTimeout
	}
	if err := d.waitReady(ctx, containerID, timeout); err != nil {
		if ctx.Err() == nil {
			fail(err.Error())
		}
		return
	}
	d.logger.Info("app database server running", "server", id, "mode", cmd.GetMode())
	d.report(&agentv1.DatabaseStatus{
		ServerId: id, State: agentv1.DatabaseState_DATABASE_STATE_RUNNING, Address: d.addr.String(), Port: int32(d.port), //nolint:gosec // G115: a port.
	})
	d.wg.Go(func() { d.watch(ctx, id, containerID) })
}

// existing returns the server's container, if any, and whether it runs.
func (d *databases) existing(ctx context.Context, id string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	info, err := d.docker.client.ContainerInspect(ctx, dbName(id), client.ContainerInspectOptions{})
	if err != nil {
		return "", false
	}
	return info.Container.ID, info.Container.State != nil && info.Container.State.Running
}

// create replaces a stopped container of the server with a new one built
// from cmd (same volume) and starts it.
func (d *databases) create(ctx context.Context, cmd *agentv1.StartDatabaseCommand) (string, error) {
	id := cmd.GetServerId()
	if err := d.ensureNetwork(ctx); err != nil {
		return "", err
	}
	pullCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	err := d.docker.ensureImage(pullCtx, cmd.GetImage())
	cancel()
	if err != nil {
		return "", fmt.Errorf("pull the database image: %w", err)
	}
	dctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	_, _ = d.docker.client.ContainerRemove(dctx, dbName(id), client.ContainerRemoveOptions{Force: true})
	port, err := network.ParsePort(strconv.Itoa(dbContainerPort) + "/tcp")
	if err != nil {
		return "", err
	}
	env := make([]string, 0, len(cmd.GetEnv())+1)
	for _, e := range cmd.GetEnv() {
		env = append(env, e.GetName()+"="+e.GetValue())
	}
	env = append(env, "NOOK_DB_MODE="+cmd.GetMode())
	pids := int64(dbPIDsLimit)
	grace := dbStopGrace
	created, err := d.docker.client.ContainerCreate(dctx, client.ContainerCreateOptions{
		Name: dbName(id),
		Config: &container.Config{
			Image: cmd.GetImage(), Env: env, ExposedPorts: network.PortSet{port: struct{}{}}, StopTimeout: &grace,
			Labels: map[string]string{ManagedLabel: "true", databaseLabel: id, nodeLabel: d.nodeID()},
		},
		HostConfig: &container.HostConfig{
			NetworkMode:    container.NetworkMode(d.netName),
			PortBindings:   network.PortMap{port: []network.PortBinding{{HostIP: d.publish, HostPort: strconv.Itoa(d.port)}}},
			Mounts:         []mount.Mount{{Type: mount.TypeVolume, Source: dbName(id), Target: "/var/lib/postgresql"}},
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			ReadonlyRootfs: true,
			Tmpfs:          map[string]string{"/tmp": dbTmpfsOptions, "/var/run/postgresql": dbTmpfsOptions},
			ShmSize:        dbShmBytes,
			RestartPolicy:  container.RestartPolicy{Name: container.RestartPolicyDisabled},
			LogConfig:      container.LogConfig{Type: "json-file", Config: map[string]string{"max-size": appLogMaxSize, "max-file": appLogMaxFiles}},
			Resources: container.Resources{
				Memory: cmd.GetMemoryBytes(), MemorySwap: cmd.GetMemoryBytes(),
				NanoCPUs: cmd.GetCpuMillicores() * 1_000_000, PidsLimit: &pids,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("create the database container: %w", err)
	}
	if _, err := d.docker.client.ContainerStart(dctx, created.ID, client.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("start the database container: %w", err)
	}
	return created.ID, nil
}

// waitReady polls `nook-db ready` until it succeeds, the container exits
// (with its last output as the reason) or timeout passes.
func (d *databases) waitReady(ctx context.Context, containerID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
		res, err := d.docker.exec(ectx, containerID, []string{"nook-db", "ready"}, nil, nil)
		cancel()
		if err == nil && res.Code == 0 {
			return nil
		}
		if !d.running(ctx, containerID) {
			return fmt.Errorf("the database server exited: %s", strings.Join(d.tail(ctx, containerID), " | "))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the database server did not accept connections within %s", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(dbReadyPoll):
		}
	}
}

// running reports whether the container runs.
func (d *databases) running(ctx context.Context, containerID string) bool {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	info, err := d.docker.client.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	return err == nil && info.Container.State != nil && info.Container.State.Running
}

// tail returns the container's last output lines.
func (d *databases) tail(ctx context.Context, containerID string) []string {
	lines := d.docker.tailLog(ctx, containerID)
	if len(lines) > dbLogLines {
		lines = lines[len(lines)-dbLogLines:]
	}
	return lines
}

// watch reports FAILED if the running server exits without being asked.
func (d *databases) watch(ctx context.Context, id, containerID string) {
	wait := d.docker.client.ContainerWait(ctx, containerID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case <-ctx.Done():
		return
	case waitErr := <-wait.Error:
		// The engine went away; reconnection reconciles.
		d.logger.Debug("stopped watching the database container", "server", id, "error", waitErr.Error())
		return
	case <-wait.Result:
	}
	d.mu.Lock()
	asked := d.stopping[id]
	d.mu.Unlock()
	if asked {
		return
	}
	msg := "the database server exited: " + strings.Join(d.tail(context.WithoutCancel(ctx), containerID), " | ")
	d.logger.Error("app database server exited", "server", id)
	d.report(&agentv1.DatabaseStatus{ServerId: id, State: agentv1.DatabaseState_DATABASE_STATE_FAILED, Message: truncateMessage(msg)})
}

// stop stops (and with remove, deletes) the server; with finalArchive the
// shutdown is clean and the WAL not yet archived is pushed first.
func (d *databases) stop(cmd *agentv1.StopDatabaseCommand) error {
	id := cmd.GetServerId()
	if !buildIDPattern.MatchString(id) {
		return errors.New("invalid server id")
	}
	d.mu.Lock()
	d.stopping[id] = true
	d.mu.Unlock()
	ctx, ok := d.claim(id, "stop")
	if !ok {
		return errors.New("an operation on this database server is in progress; try again")
	}
	d.wg.Go(func() {
		defer d.release(id)
		finalWAL, err := d.stopServer(ctx, id, cmd.GetFinalArchive(), cmd.GetRemove())
		if err != nil {
			d.logger.Error("could not stop the app database server", "server", id, "error", err.Error())
			d.report(&agentv1.DatabaseStatus{ServerId: id, State: agentv1.DatabaseState_DATABASE_STATE_FAILED, Message: truncateMessage(err.Error())})
			return
		}
		d.logger.Info("app database server stopped", "server", id, "final_wal", finalWAL, "removed", cmd.GetRemove())
		d.report(&agentv1.DatabaseStatus{ServerId: id, State: agentv1.DatabaseState_DATABASE_STATE_STOPPED, FinalWal: finalWAL})
	})
	return nil
}

func (d *databases) stopServer(ctx context.Context, id string, finalArchive, remove bool) (string, error) {
	info, err := d.docker.client.ContainerInspect(ctx, dbName(id), client.ContainerInspectOptions{})
	if err != nil {
		if remove {
			d.removeVolume(ctx, id)
		}
		return "", nil // no container: already stopped
	}
	grace := dbStopGrace
	sctx, cancel := context.WithTimeout(ctx, (dbStopGrace+30)*time.Second)
	_, err = d.docker.client.ContainerStop(sctx, info.Container.ID, client.ContainerStopOptions{Timeout: &grace})
	cancel()
	if err != nil {
		return "", fmt.Errorf("stop the database container: %w", err)
	}
	var finalWAL string
	if finalArchive {
		if finalWAL, err = d.finalArchive(ctx, id, info.Container.Config.Image, info.Container.Config.Env); err != nil {
			return "", err
		}
	}
	if remove {
		rctx, cancel := context.WithTimeout(ctx, dockerTimeout)
		_, _ = d.docker.client.ContainerRemove(rctx, info.Container.ID, client.ContainerRemoveOptions{Force: true})
		cancel()
		d.removeVolume(ctx, id)
	}
	return finalWAL, nil
}

func (d *databases) removeVolume(ctx context.Context, id string) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	if _, err := d.docker.client.VolumeRemove(ctx, dbName(id), client.VolumeRemoveOptions{Force: true}); err != nil {
		d.logger.Warn("could not remove the database volume", "server", id, "error", err.Error())
	}
}

// finalArchive runs `nook-db final-archive` in a one-off container on the
// stopped server's volume and returns the last segment it pushed.
func (d *databases) finalArchive(ctx context.Context, id, image string, env []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	code, out, err := d.docker.runOnce(ctx, client.ContainerCreateOptions{
		Config: &container.Config{
			Image: image, Env: env, Cmd: []string{"final-archive"},
			Labels: map[string]string{ManagedLabel: "true", nodeLabel: d.nodeID()},
		},
		HostConfig: &container.HostConfig{
			NetworkMode:    container.NetworkMode(d.netName),
			Mounts:         []mount.Mount{{Type: mount.TypeVolume, Source: dbName(id), Target: "/var/lib/postgresql"}},
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			ReadonlyRootfs: true,
			Tmpfs:          map[string]string{"/tmp": dbTmpfsOptions, "/var/run/postgresql": dbTmpfsOptions},
		},
	})
	if err != nil {
		return "", fmt.Errorf("final archive: %w", err)
	}
	var last string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); walSegmentRegexp.MatchString(line) {
			last = line
		}
	}
	if code != 0 || last == "" {
		return "", fmt.Errorf("final archive failed (exit %d): %s", code, truncateMessage(strings.TrimSpace(out)))
	}
	return last, nil
}

// reports lists the database server containers on the node.
func (d *databases) reports(ctx context.Context) []*agentv1.DatabaseReport {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	// Only this node's: another node's server may share the engine.
	list, err := d.docker.client.ContainerList(ctx, client.ContainerListOptions{
		All: true, Filters: client.Filters{}.Add("label", databaseLabel).Add("label", nodeLabel+"="+d.nodeID()),
	})
	if err != nil {
		d.logger.Warn("could not list database containers for reconciliation", "error", err.Error())
		return nil
	}
	out := make([]*agentv1.DatabaseReport, 0, len(list.Items))
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range list.Items {
		c := &list.Items[i]
		if id := c.Labels[databaseLabel]; buildIDPattern.MatchString(id) {
			out = append(out, &agentv1.DatabaseReport{
				ServerId: id, Running: c.State == container.StateRunning, BackupRunning: d.busy["backup:"+id] != "",
			})
		}
	}
	return out
}

// adopt watches the server containers that run after an agent restart.
func (d *databases) adopt(ctx context.Context) {
	for _, r := range d.reports(ctx) {
		if !r.GetRunning() {
			continue
		}
		id := r.GetServerId()
		if containerID, running := d.existing(ctx, id); running {
			d.wg.Go(func() { d.watch(ctx, id, containerID) })
		}
	}
}

// close stops accepting operations and waits briefly for running ones,
// which end with the agent's context.
func (d *databases) close() {
	d.mu.Lock()
	d.ctx = nil
	d.mu.Unlock()
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopGrace):
	}
}

func truncateMessage(s string) string {
	if len(s) > 900 {
		return s[:900] + "..."
	}
	return s
}
