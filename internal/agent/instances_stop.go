package agent

// Stopping app instances: after a drain, keeping the container for an app
// going to sleep or removing it, and ordering starts that arrive meanwhile.

import (
	"context"
	"errors"
	"time"

	"github.com/moby/moby/client"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// stop stops and removes an instance's container after drain and reports
// it STOPPED. Unknown instances (strays) are removed too. With keep, the
// container is stopped but kept and not reported (an app going to sleep):
// a later start of the same instance starts it again (createOrReuse).
func (m *instances) stop(id string, drain time.Duration, keep bool) error {
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
			// A stop after a queued start wins; a removal wins over keeping.
			inst.next = nil
			inst.keep = inst.keep && keep
			m.mu.Unlock()
			return nil
		}
		inst.phase = phaseStopping
		inst.keep = keep
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
		m.finishStop(context.WithoutCancel(ctx), id, inst, keep)
	})
	return nil
}

// finishStop stops (keep) or removes an instance's container, then runs a
// start queued meanwhile or reports the instance stopped. inst is nil for
// a container the agent does not track.
func (m *instances) finishStop(ctx context.Context, id string, inst *instance, keep bool) {
	if inst != nil {
		m.mu.Lock()
		keep = inst.keep
		m.mu.Unlock()
	}
	if keep {
		m.stopByName(ctx, id)
	} else {
		m.removeByName(ctx, id)
	}
	m.mu.Lock()
	var next *agentv1.StartInstanceCommand
	removeToo := false
	if inst != nil {
		next = inst.next
		removeToo = keep && !inst.keep // a removal arrived while stopping
	}
	delete(m.m, id)
	m.mu.Unlock()
	if removeToo {
		m.removeByName(ctx, id)
		keep = false
	}
	m.logger.Info("app instance stopped", "instance", id)
	if next != nil {
		if err := m.start(next); err != nil { //nolint:contextcheck // the instance outlives the stop: the manager owns its context
			m.report(&agentv1.InstanceStatus{InstanceId: id, State: agentv1.InstanceState_INSTANCE_STATE_FAILED, Message: "the node could not start the app: " + err.Error()})
		}
		return
	}
	// A kept container is an app going to sleep, which the control plane
	// records without waiting for the agent; reporting it could overtake a
	// wake of the same instance and end it.
	if !keep {
		m.report(&agentv1.InstanceStatus{InstanceId: id, State: agentv1.InstanceState_INSTANCE_STATE_STOPPED})
	}
}

// stopByName stops an instance's container, if it exists, and keeps it.
func (m *instances) stopByName(ctx context.Context, instanceID string) {
	stopCtx, cancel := context.WithTimeout(ctx, dockerTimeout+appStopGrace*time.Second)
	defer cancel()
	grace := appStopGrace
	if _, err := m.docker.client.ContainerStop(stopCtx, containerName(instanceID), client.ContainerStopOptions{Timeout: &grace}); err != nil {
		m.logger.Warn("could not stop an app container", "instance", instanceID, "error", err.Error())
	}
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
