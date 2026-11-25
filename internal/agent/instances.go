package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// phase is where an instance is in its life on this node.
type phase int

const (
	phaseStarting   phase = iota // pulling, creating, waiting for health
	phaseRunning                 // healthy; a crash is noticed
	phaseRestarting              // crashed; waiting for the backoff or the health check
	phaseStopping                // asked to stop
	phaseCrashed                 // crash loop: no longer restarted
)

// instance is an app instance this agent runs.
type instance struct {
	id          string
	appID       string
	containerID string
	port        int32
	healthPath  string
	startup     time.Duration
	phase       phase
	restarts    int32
	sched       *restartScheduler
	// cancel ends the current start or restart; done is closed when it
	// returned (a stop waits for it before touching the container).
	cancel context.CancelFunc
	done   chan struct{}
}

// instances runs app containers and keeps them up: it starts them behind
// a health check, restarts crashed ones with a backoff, gives up on crash
// loops and stops them after a drain period.
type instances struct {
	docker    *docker
	puller    *puller
	outbox    *outbox
	logger    *slog.Logger
	nodeID    func() string
	advertise netip.Addr
	policy    crashPolicy
	clock     clock

	// netMu orders creating containers on app networks against removing
	// those networks once unused, so a new container never loses its
	// network to the removal of an old one.
	netMu sync.Mutex

	mu   sync.Mutex
	ctx  context.Context
	m    map[string]*instance
	wg   sync.WaitGroup
	logs map[string]context.CancelFunc
}

var errStopping = errors.New("the instance is stopping")

func (m *instances) report(s *agentv1.InstanceStatus) {
	m.outbox.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_InstanceStatus{InstanceStatus: s}})
}

// start runs an instance, or does nothing if it already runs. The outcome
// is reported later (HEALTHY or FAILED).
func (m *instances) start(cmd *agentv1.StartInstanceCommand) error {
	if err := validateStart(cmd); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil {
		return errShuttingDown
	}
	inst, ok := m.m[cmd.GetInstanceId()]
	if ok {
		switch inst.phase {
		case phaseStarting, phaseRunning, phaseRestarting:
			return nil
		case phaseStopping:
			return errStopping
		default: // crashed: started again on request
		}
	} else {
		inst = &instance{id: cmd.GetInstanceId(), sched: &restartScheduler{clock: m.clock, policy: m.policy}}
		m.m[inst.id] = inst
	}
	inst.appID, inst.port, inst.healthPath = cmd.GetAppId(), cmd.GetPort(), cmd.GetHealthCheckPath()
	inst.startup = min(max(cmd.GetStartupTimeout().AsDuration(), time.Second), maxStartup)
	inst.phase = phaseStarting
	ctx, cancel := context.WithCancel(m.ctx)
	inst.cancel, inst.done = cancel, make(chan struct{})
	done := inst.done
	m.wg.Go(func() {
		defer close(done)
		defer cancel()
		m.launch(ctx, inst, cmd)
	})
	return nil
}

// launch pulls, creates (or reuses) and starts the container, then waits
// for its health check.
func (m *instances) launch(ctx context.Context, inst *instance, cmd *agentv1.StartInstanceCommand) {
	fail := func(msg string, startupLog []string) {
		if ctx.Err() != nil {
			return // stopped or shutting down: the stop reports
		}
		m.mu.Lock()
		delete(m.m, inst.id)
		m.mu.Unlock()
		m.report(&agentv1.InstanceStatus{InstanceId: inst.id, State: agentv1.InstanceState_INSTANCE_STATE_FAILED, Message: msg, StartupLog: startupLog})
		m.logger.Warn("app instance failed to start", "instance", inst.id, "reason", msg)
	}
	ref, err := m.puller.ensure(ctx, cmd.GetRegistry(), cmd.GetRepository(), cmd.GetImageDigest(), cmd.GetRegistryToken())
	if err != nil {
		m.logger.Warn("image pull failed", "instance", inst.id, "error", err.Error())
		fail("the node could not pull the image: "+err.Error(), nil)
		return
	}
	id, err := m.createOrReuse(ctx, cmd, ref)
	if err != nil {
		m.logger.Warn("could not create the app container", "instance", inst.id, "error", err.Error())
		fail("the node could not create the container", nil)
		return
	}
	m.mu.Lock()
	inst.containerID = id
	m.mu.Unlock()
	startCtx, cancel := context.WithTimeout(ctx, dockerTimeout)
	_, err = m.docker.client.ContainerStart(startCtx, id, client.ContainerStartOptions{})
	cancel()
	if err != nil {
		m.logger.Warn("could not start the app container", "instance", inst.id, "error", err.Error())
		m.removeContainer(context.WithoutCancel(ctx), id, inst.appID)
		fail("the container could not be started", nil)
		return
	}
	port, err := m.hostPort(ctx, id, cmd.GetPort())
	if err != nil {
		// A container that already exited has no published port: report
		// the exit, not the port.
		reason := "the app's port could not be published"
		if why, running := m.containerState(ctx, id); !running {
			reason = why
		}
		lines := m.tailLog(context.WithoutCancel(ctx), id)
		m.removeContainer(context.WithoutCancel(ctx), id, inst.appID)
		fail(reason, lines)
		return
	}
	m.report(&agentv1.InstanceStatus{InstanceId: inst.id, State: agentv1.InstanceState_INSTANCE_STATE_STARTING, ContainerId: id, HostPort: int32(port)}) //nolint:gosec // G115: a TCP port.
	if err := m.waitHealthy(ctx, id, port, cmd.GetHealthCheckPath(), inst.startup); err != nil {
		lines := m.tailLog(context.WithoutCancel(ctx), id)
		if ctx.Err() == nil {
			m.removeContainer(context.WithoutCancel(ctx), id, inst.appID)
		}
		fail(err.Error(), lines)
		return
	}
	m.mu.Lock()
	ok := inst.phase == phaseStarting
	if ok {
		inst.phase = phaseRunning
	}
	restarts := inst.restarts
	m.mu.Unlock()
	if !ok {
		return
	}
	m.report(&agentv1.InstanceStatus{InstanceId: inst.id, State: agentv1.InstanceState_INSTANCE_STATE_HEALTHY, ContainerId: id, HostPort: int32(port), RestartCount: restarts}) //nolint:gosec // G115: a TCP port.
	m.logger.Info("app instance is healthy", "instance", inst.id, "container", id, "host_port", port)
}

func exitedErrorOr(err error, def string) string {
	var ex exitedError
	if errors.As(err, &ex) {
		return ex.reason
	}
	return def
}

// createOrReuse returns the instance's container, creating it if needed
// (a restarted agent or a repeated command finds it).
func (m *instances) createOrReuse(ctx context.Context, cmd *agentv1.StartInstanceCommand, ref string) (string, error) {
	inspectCtx, cancel := context.WithTimeout(ctx, dockerTimeout)
	info, err := m.docker.client.ContainerInspect(inspectCtx, containerName(cmd.GetInstanceId()), client.ContainerInspectOptions{})
	cancel()
	if err == nil {
		return info.Container.ID, nil
	}
	m.netMu.Lock()
	defer m.netMu.Unlock()
	netName, err := m.ensureAppNetwork(ctx, cmd.GetAppId())
	if err != nil {
		return "", err
	}
	spec, err := m.appContainerSpec(cmd, ref, netName)
	if err != nil {
		return "", err
	}
	createCtx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	created, err := m.docker.client.ContainerCreate(createCtx, spec)
	if err != nil {
		return "", fmt.Errorf("create container: %w", err)
	}
	return created.ID, nil
}

// setPhase moves inst from one phase to another, reporting whether it was
// still in from (a stop may have intervened).
func (m *instances) setPhase(inst *instance, from, to phase) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inst.phase != from {
		return false
	}
	inst.phase = to
	return true
}

// died handles a container exit noticed through Docker events.
func (m *instances) died(id string) {
	m.mu.Lock()
	inst, ok := m.m[id]
	if !ok || inst.phase != phaseRunning {
		m.mu.Unlock()
		return
	}
	inst.phase = phaseRestarting
	m.mu.Unlock()
	reason, _ := m.containerState(context.Background(), inst.containerID)
	m.crash(inst, reason)
}

// crash applies the crash policy to an instance in phaseRestarting.
func (m *instances) crash(inst *instance, reason string) {
	m.mu.Lock()
	inst.restarts++
	restarts := inst.restarts
	m.mu.Unlock()
	gaveUp := false
	delay, count := inst.sched.crashed(func() { m.restart(inst) }, func(int) { gaveUp = true })
	if gaveUp {
		if !m.setPhase(inst, phaseRestarting, phaseCrashed) {
			return
		}
		msg := fmt.Sprintf("%s; it crashed %d times within %s and is no longer restarted", reason, count, m.policy.Window)
		m.report(&agentv1.InstanceStatus{InstanceId: inst.id, State: agentv1.InstanceState_INSTANCE_STATE_CRASHED, ContainerId: inst.containerID, RestartCount: restarts, Message: msg})
		m.logger.Warn("app instance is in a crash loop", "instance", inst.id, "crashes", count)
		return
	}
	msg := fmt.Sprintf("%s; restarting in %s", reason, delay.Round(time.Millisecond))
	m.report(&agentv1.InstanceStatus{InstanceId: inst.id, State: agentv1.InstanceState_INSTANCE_STATE_UNHEALTHY, ContainerId: inst.containerID, RestartCount: restarts, Message: msg})
	m.logger.Info("app instance crashed; restarting", "instance", inst.id, "restarts", restarts, "delay", delay.String())
}

// restart starts a crashed instance's container again after its backoff.
func (m *instances) restart(inst *instance) {
	m.mu.Lock()
	if inst.phase != phaseRestarting || m.ctx == nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	inst.cancel, inst.done = cancel, make(chan struct{})
	done := inst.done
	m.mu.Unlock()
	m.wg.Go(func() {
		defer close(done)
		defer cancel()
		startCtx, cancelStart := context.WithTimeout(ctx, dockerTimeout)
		_, err := m.docker.client.ContainerStart(startCtx, inst.containerID, client.ContainerStartOptions{})
		cancelStart()
		if err != nil {
			if ctx.Err() == nil {
				m.crash(inst, "the container could not be restarted") //nolint:contextcheck // restarts run on the manager's own context.
			}
			return
		}
		port, err := m.hostPort(ctx, inst.containerID, inst.port)
		if err == nil {
			err = m.waitHealthy(ctx, inst.containerID, port, inst.healthPath, inst.startup)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			// Unhealthy after a restart counts as another crash.
			stopCtx, cancelStop := context.WithTimeout(ctx, dockerTimeout+appStopGrace*time.Second)
			grace := 0
			_, _ = m.docker.client.ContainerStop(stopCtx, inst.containerID, client.ContainerStopOptions{Timeout: &grace})
			cancelStop()
			m.crash(inst, exitedErrorOr(err, err.Error())) //nolint:contextcheck // restarts run on the manager's own context.
			return
		}
		m.mu.Lock()
		ok := inst.phase == phaseRestarting
		if ok {
			inst.phase = phaseRunning
		}
		restarts := inst.restarts
		m.mu.Unlock()
		if ok {
			m.report(&agentv1.InstanceStatus{InstanceId: inst.id, State: agentv1.InstanceState_INSTANCE_STATE_HEALTHY,
				ContainerId: inst.containerID, HostPort: int32(port), RestartCount: restarts}) //nolint:gosec // G115: a TCP port.
		}
	})
}

// stop stops and removes an instance's container after drain; the result
// is reported as STOPPED. Unknown instances (strays) are removed too.
func (m *instances) stop(id string, drain time.Duration) error {
	if !buildIDPattern.MatchString(id) {
		return errors.New("invalid instance id")
	}
	m.mu.Lock()
	if m.ctx == nil {
		m.mu.Unlock()
		return errShuttingDown
	}
	inst := m.m[id]
	var wait chan struct{}
	var cancelRun context.CancelFunc
	if inst != nil {
		if inst.phase == phaseStopping {
			m.mu.Unlock()
			return nil
		}
		inst.phase = phaseStopping
		inst.sched.cancel()
		wait, cancelRun = inst.done, inst.cancel
	}
	ctx := m.ctx
	m.mu.Unlock()
	m.wg.Go(func() {
		select {
		case <-ctx.Done():
			return // the control plane asks again once the agent is back
		case <-time.After(min(max(drain, 0), 10*time.Minute)):
		}
		if cancelRun != nil {
			cancelRun()
		}
		if wait != nil {
			<-wait
		}
		m.removeByName(context.WithoutCancel(ctx), id)
		m.mu.Lock()
		delete(m.m, id)
		m.mu.Unlock()
		m.report(&agentv1.InstanceStatus{InstanceId: id, State: agentv1.InstanceState_INSTANCE_STATE_STOPPED})
		m.logger.Info("app instance stopped", "instance", id)
	})
	return nil
}

// removeByName stops and removes an instance's container, if it exists,
// and the app's network once unused.
func (m *instances) removeByName(ctx context.Context, instanceID string) {
	inspectCtx, cancel := context.WithTimeout(ctx, dockerTimeout)
	info, err := m.docker.client.ContainerInspect(inspectCtx, containerName(instanceID), client.ContainerInspectOptions{})
	cancel()
	if err != nil {
		return
	}
	appID := ""
	if info.Container.Config != nil {
		appID = info.Container.Config.Labels[appLabel]
	}
	m.removeContainer(ctx, info.Container.ID, appID)
}

func (m *instances) removeContainer(ctx context.Context, id, appID string) {
	stopCtx, cancel := context.WithTimeout(ctx, dockerTimeout+appStopGrace*time.Second)
	grace := appStopGrace
	_, _ = m.docker.client.ContainerStop(stopCtx, id, client.ContainerStopOptions{Timeout: &grace})
	cancel()
	rmCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	m.netMu.Lock()
	defer m.netMu.Unlock()
	if _, err := m.docker.client.ContainerRemove(rmCtx, id, client.ContainerRemoveOptions{Force: true}); err != nil {
		m.logger.Warn("could not remove an app container", "container", id, "error", err.Error())
	}
	if appID != "" {
		m.removeAppNetwork(ctx, appID)
	}
}

// listOwn lists this node's app containers.
func (m *instances) listOwn(ctx context.Context) ([]containerSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout)
	defer cancel()
	list, err := m.docker.client.ContainerList(ctx, client.ContainerListOptions{
		All: true, Filters: client.Filters{}.Add("label", nodeLabel+"="+m.nodeID()).Add("label", instanceLabel),
	})
	if err != nil {
		return nil, unreachable(err)
	}
	out := make([]containerSummary, 0, len(list.Items))
	for i := range list.Items {
		c := &list.Items[i]
		s := containerSummary{id: c.ID, instanceID: c.Labels[instanceLabel], appID: c.Labels[appLabel], running: c.State == "running", labels: c.Labels}
		for _, p := range c.Ports {
			if p.PublicPort != 0 && p.IP.Unmap() == m.advertise {
				s.hostPort = int32(p.PublicPort)
			}
		}
		out = append(out, s)
	}
	return out, nil
}

type containerSummary struct {
	id, instanceID, appID string
	running               bool
	hostPort              int32
	labels                map[string]string
}

// reports describes the node's app containers for a Hello.
func (m *instances) reports(ctx context.Context) []*agentv1.InstanceReport {
	list, err := m.listOwn(ctx)
	if err != nil {
		m.logger.Warn("could not list app containers for reconciliation", "error", err.Error())
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*agentv1.InstanceReport, 0, len(list))
	for _, c := range list {
		r := &agentv1.InstanceReport{InstanceId: c.instanceID, ContainerId: c.id, Running: c.running, HostPort: c.hostPort}
		if inst, ok := m.m[c.instanceID]; ok {
			r.RestartCount = inst.restarts
			r.Stopping = inst.phase == phaseStopping
			// A container between crash and restart counts as running: the
			// agent is about to start it again.
			r.Running = r.Running || inst.phase == phaseRestarting || inst.phase == phaseStarting
		}
		out = append(out, r)
	}
	return out
}

// adopt takes over the running app containers of this node after an agent
// restart, so their crashes are handled again.
func (m *instances) adopt(ctx context.Context) {
	list, err := m.listOwn(ctx)
	if err != nil {
		m.logger.Warn("could not list app containers to adopt", "error", err.Error())
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range list {
		if !c.running || !buildIDPattern.MatchString(c.instanceID) {
			continue
		}
		if _, ok := m.m[c.instanceID]; ok {
			continue
		}
		port, _ := strconv.Atoi(c.labels[portLabel])
		startup, err := time.ParseDuration(c.labels[startupTimeoutLabel])
		if err != nil {
			startup = time.Minute
		}
		m.m[c.instanceID] = &instance{
			id: c.instanceID, appID: c.appID, containerID: c.id, port: int32(port), healthPath: c.labels[healthPathLabel], //nolint:gosec // G115: a TCP port.
			startup: startup, phase: phaseRunning, sched: &restartScheduler{clock: m.clock, policy: m.policy},
		}
		m.logger.Info("adopted a running app container", "instance", c.instanceID, "container", c.id)
	}
}

// watch follows container exits until ctx ends, re-subscribing after
// errors (for example a Docker engine restart). onReconnect runs after
// every re-subscription, then exits missed meanwhile are handled.
func (m *instances) watch(ctx context.Context, onReconnect func(context.Context)) {
	first := true
	for ctx.Err() == nil {
		res := m.docker.client.Events(ctx, client.EventsListOptions{Filters: client.Filters{}.
			Add("type", string(events.ContainerEventType)).Add("event", "die").Add("label", nodeLabel+"="+m.nodeID())})
		if !first {
			onReconnect(ctx)
			m.sweep(ctx)
		}
		first = false
	loop:
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-res.Messages:
				if id := msg.Actor.Attributes[instanceLabel]; id != "" {
					m.died(id) //nolint:contextcheck // restarts run on the manager's own context.
				}
			case err := <-res.Err:
				if ctx.Err() == nil {
					m.logger.Warn("docker event stream ended; resubscribing", "error", err.Error())
				}
				break loop
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

// sweep handles running instances whose containers stopped while the
// event stream was down.
func (m *instances) sweep(ctx context.Context) {
	list, err := m.listOwn(ctx)
	if err != nil {
		return
	}
	running := map[string]bool{}
	for _, c := range list {
		running[c.instanceID] = c.running
	}
	m.mu.Lock()
	var dead []string
	for id, inst := range m.m {
		if inst.phase == phaseRunning && !running[id] {
			dead = append(dead, id)
		}
	}
	m.mu.Unlock()
	for _, id := range dead {
		m.died(id) //nolint:contextcheck // restarts run on the manager's own context.
	}
}

// close stops restarts and waits for running operations, at most
// stopGrace. Containers keep running: apps serve while the agent is away.
func (m *instances) close() {
	m.mu.Lock()
	m.ctx = nil
	for _, inst := range m.m {
		inst.sched.cancel()
		if inst.cancel != nil {
			inst.cancel()
		}
	}
	for _, cancel := range m.logs {
		cancel()
	}
	m.mu.Unlock()
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopGrace):
		m.logger.Warn("app operations did not stop in time")
	}
}
