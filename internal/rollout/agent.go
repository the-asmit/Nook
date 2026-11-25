package rollout

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"uuid"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Reserved environment variables Nook sets in every app container.
const (
	EnvPort       = "PORT"
	EnvApp        = "NOOK_APP"
	EnvDeployment = "NOOK_DEPLOYMENT"
)

// environment decrypts a deployment's environment snapshot and adds the
// reserved variables. The plaintext only ever goes into the start command
// (sent over mTLS); it is never logged or stored.
func (c *Controller) environment(ctx context.Context, dep *store.Deployment, app *store.App) ([]*agentv1.EnvVar, error) {
	var env []*agentv1.EnvVar
	if dep.EnvSnapshotID != nil {
		vars, err := c.Store.ListSnapshotVars(ctx, *dep.EnvSnapshotID)
		if err != nil {
			return nil, fmt.Errorf("read environment snapshot: %w", err)
		}
		for _, v := range vars {
			plain, err := c.Keyring.Open(int(v.KeyVersion), secrets.EnvAAD(app.ID, v.Key), v.Value)
			if err != nil {
				// Names a variable, never a value.
				return nil, fmt.Errorf("environment variable %s: %w", v.Key, err)
			}
			env = append(env, &agentv1.EnvVar{Name: v.Key, Value: string(plain)})
		}
	}
	return append(env,
		&agentv1.EnvVar{Name: EnvPort, Value: strconv.Itoa(int(app.Port))},
		&agentv1.EnvVar{Name: EnvApp, Value: app.Slug},
		&agentv1.EnvVar{Name: EnvDeployment, Value: strconv.Itoa(int(dep.Number))},
	), nil
}

// sendStart asks the instance's node to run it. A node that cannot take
// the command fails the instance.
func (c *Controller) sendStart(ctx context.Context, dep *store.Deployment, app *store.App, inst *store.AppInstance) error {
	cmd, err := c.startCommand(ctx, dep, app, inst)
	if err != nil {
		return err
	}
	if inst.NodeID == nil {
		return c.instanceFailed(ctx, inst, "its node was removed")
	}
	res, err := c.Commander.Dispatch(ctx, *inst.NodeID, cmd, dispatchTimeout)
	if err == nil && res.GetError() == nil {
		if markErr := c.Store.MarkInstanceStartSent(ctx, inst.ID); markErr != nil {
			return fmt.Errorf("mark start sent: %w", markErr)
		}
		c.Notes.Note(ctx, dep.ID, "", "starting on node "+inst.NodeName)
		return nil
	}
	reason := "node " + inst.NodeName + " could not start the app"
	if res.GetError() != nil {
		reason += ": " + res.GetError().GetMessage()
	} else if err != nil {
		reason += ": " + err.Error()
	}
	return c.instanceFailed(ctx, inst, reason)
}

func (c *Controller) instanceFailed(ctx context.Context, inst *store.AppInstance, reason string) error {
	if _, err := c.Store.InstanceFailed(ctx, store.InstanceFailedParams{ID: inst.ID, LastError: truncate(reason, maxMessage)}); err != nil && !store.IsNotFound(err) {
		return fmt.Errorf("fail instance: %w", err)
	}
	c.Wake(ctx, inst.DeploymentID)
	return nil
}

func (c *Controller) startCommand(ctx context.Context, dep *store.Deployment, app *store.App, inst *store.AppInstance) (*agentv1.Command, error) {
	if dep.ImageDigest == nil {
		return nil, fmt.Errorf("deployment %s has no image", dep.ID)
	}
	env, err := c.environment(ctx, dep, app)
	if err != nil {
		return nil, err
	}
	startup := time.Duration(app.StartupTimeoutSeconds) * time.Second
	repo := apps.RepositoryName(app.WorkspaceID, app.ID)
	token, err := c.Issuer.Token("node:"+inst.NodeName, c.cfg.PullTimeout+startup+lostGrace, registry.RepositoryAccess(repo, registry.ActionPull))
	if err != nil {
		return nil, err
	}
	return &agentv1.Command{Kind: &agentv1.Command_StartInstance{StartInstance: &agentv1.StartInstanceCommand{
		InstanceId: inst.ID.String(), DeploymentId: dep.ID.String(), AppId: app.ID.String(), WorkspaceId: app.WorkspaceID.String(),
		AppSlug: app.Slug, DeploymentNumber: dep.Number,
		Registry: c.RegistryAddr, Repository: repo, ImageDigest: *dep.ImageDigest, RegistryToken: token,
		Port: app.Port, HealthCheckPath: app.HealthCheckPath, StartupTimeout: durationpb.New(startup),
		MemoryBytes: int64(inst.MemoryMb) << 20, CpuMillicores: int64(inst.CpuMillicores), ReadOnlyRootfs: app.ReadOnlyRootfs,
		Env: env,
	}}}, nil
}

// stopInstance marks an instance stopping and asks its node to stop it
// after drain. An unreachable node gets the request again when its agent
// reconnects (reconciliation).
func (c *Controller) stopInstance(ctx context.Context, inst *store.AppInstance, drain time.Duration) {
	if inst.State != store.InstanceStateStopping {
		if _, err := c.Store.RequestInstanceStop(ctx, inst.ID); err != nil {
			if !store.IsNotFound(err) {
				c.Logger.WarnContext(ctx, "could not stop instance", "instance", inst.ID.String(), "error", err.Error())
			}
			return
		}
	}
	if inst.NodeID == nil {
		if _, err := c.Store.InstanceStopped(ctx, inst.ID); err != nil && !store.IsNotFound(err) {
			c.Logger.WarnContext(ctx, "could not record stopped instance", "instance", inst.ID.String(), "error", err.Error())
		}
		return
	}
	c.sendStop(ctx, *inst.NodeID, inst.ID.String(), drain)
}

func (c *Controller) sendStop(ctx context.Context, nodeID uuid.UUID, instanceID string, drain time.Duration) {
	cmd := &agentv1.Command{Kind: &agentv1.Command_StopInstance{StopInstance: &agentv1.StopInstanceCommand{
		InstanceId: instanceID, Drain: durationpb.New(drain),
	}}}
	res, err := c.Commander.Dispatch(ctx, nodeID, cmd, dispatchTimeout)
	if err == nil && res.GetError() != nil {
		err = fmt.Errorf("%s", res.GetError().GetMessage())
	}
	if err != nil {
		c.Logger.WarnContext(ctx, "could not ask the node to stop an instance; it is retried when the agent reconnects",
			"instance", instanceID, "node_id", nodeID.String(), "error", err.Error())
	}
}

// InstanceStatus records a state change an agent reported for one of its
// instances and wakes the deployment's owner. Reports about instances the
// node does not run are ignored.
func (c *Controller) InstanceStatus(ctx context.Context, nodeID uuid.UUID, m *agentv1.InstanceStatus) error {
	id, ok := parseID(m.GetInstanceId())
	if !ok {
		return nil // not an instance of ours
	}
	inst, err := c.Store.GetInstance(ctx, id)
	if store.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read instance: %w", err)
	}
	if inst.NodeID == nil || *inst.NodeID != nodeID {
		return nil
	}
	msg := sanitize(m.GetMessage())
	restarts := max(m.GetRestartCount(), 0)
	containerID := sanitizeID(m.GetContainerId())
	var port *int32
	if p := m.GetHostPort(); p > 0 && p <= 65535 {
		port = &p
	}
	switch m.GetState() {
	case agentv1.InstanceState_INSTANCE_STATE_STARTING:
		err = c.Store.SetInstanceContainer(ctx, store.SetInstanceContainerParams{ID: id, ContainerID: containerID, HostPort: port})
	case agentv1.InstanceState_INSTANCE_STATE_HEALTHY:
		_, err = c.Store.InstanceRunning(ctx, store.InstanceRunningParams{ID: id, ContainerID: containerID, HostPort: port, RestartCount: restarts})
	case agentv1.InstanceState_INSTANCE_STATE_UNHEALTHY:
		_, err = c.Store.InstanceUnhealthy(ctx, store.InstanceUnhealthyParams{ID: id, RestartCount: restarts, LastError: msg})
	case agentv1.InstanceState_INSTANCE_STATE_CRASHED:
		_, err = c.Store.InstanceCrashed(ctx, store.InstanceCrashedParams{ID: id, RestartCount: restarts, LastError: msg})
	case agentv1.InstanceState_INSTANCE_STATE_FAILED:
		_, err = c.Store.InstanceFailed(ctx, store.InstanceFailedParams{ID: id, LastError: orDefault(msg, "the app did not start"), StartupLog: startupLog(m.GetStartupLog())})
	case agentv1.InstanceState_INSTANCE_STATE_STOPPED:
		_, err = c.Store.InstanceStopped(ctx, id)
	default:
		return nil
	}
	if err != nil && !store.IsNotFound(err) {
		return fmt.Errorf("record instance state: %w", err)
	}
	c.Wake(ctx, inst.DeploymentID)
	return nil
}

// AgentConnected reconciles a node's app containers with what the control
// plane wants on it when its agent (re)connects: containers of instances
// it should not have are removed, instances it should run but whose
// container is missing or not running are started again, and stopping
// instances whose container is gone are recorded as stopped.
func (c *Controller) AgentConnected(ctx context.Context, nodeID uuid.UUID, reports []*agentv1.InstanceReport) {
	want, err := c.Store.ListInstancesOnNode(ctx, &nodeID)
	if err != nil {
		c.Logger.WarnContext(ctx, "could not reconcile the node's instances", "node_id", nodeID.String(), "error", err.Error())
		return
	}
	wanted := make(map[string]*store.AppInstance, len(want))
	for i := range want {
		wanted[want[i].ID.String()] = &want[i]
	}
	seen := map[string]bool{}
	for _, r := range reports {
		seen[r.GetInstanceId()] = true
		inst, ok := wanted[r.GetInstanceId()]
		switch {
		case !ok:
			c.Logger.InfoContext(ctx, "removing a container the node should not run", "node_id", nodeID.String(), "instance", r.GetInstanceId())
			c.sendStop(ctx, nodeID, r.GetInstanceId(), 0)
		case inst.State == store.InstanceStateStopping:
			if !r.GetStopping() {
				c.sendStop(ctx, nodeID, r.GetInstanceId(), 0)
			}
		case inst.State == store.InstanceStateCrashed:
			// Kept, stopped, for its logs.
		case !r.GetRunning() && inst.StartSentAt != nil:
			c.restart(ctx, inst, "its container was not running")
		}
	}
	for id, inst := range wanted {
		if seen[id] {
			continue
		}
		switch inst.State {
		case store.InstanceStateStopping, store.InstanceStateCrashed:
			if _, err := c.Store.InstanceStopped(ctx, inst.ID); err != nil && !store.IsNotFound(err) {
				c.Logger.WarnContext(ctx, "could not record stopped instance", "instance", id, "error", err.Error())
			}
		default:
			if inst.StartSentAt != nil {
				c.restart(ctx, inst, "its container was missing")
			}
		}
	}
}

// restart sends the start command of an instance again (it is idempotent
// on the agent).
func (c *Controller) restart(ctx context.Context, inst *store.AppInstance, why string) {
	dep, err := c.Store.GetDeploymentByID(ctx, inst.DeploymentID)
	if err != nil {
		return
	}
	app, err := c.Store.GetAppByID(ctx, inst.AppID)
	if err != nil {
		return
	}
	c.Logger.InfoContext(ctx, "restarting an instance on its node", "instance", inst.ID.String(), "node", inst.NodeName, "reason", why)
	if err := c.sendStart(ctx, &dep, &app, inst); err != nil {
		c.Logger.WarnContext(ctx, "could not restart instance", "instance", inst.ID.String(), "error", err.Error())
	}
}

func parseID(s string) (uuid.UUID, bool) {
	id, err := uuid.Parse(s)
	return id, err == nil
}

func startupLog(lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		l = strings.ToValidUTF8(l, "?")
		if b.Len()+len(l)+1 > maxStartupLog {
			break
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, strings.ToValidUTF8(s, "?"))
	return strings.TrimSpace(truncate(s, maxMessage))
}

// sanitizeID keeps a Docker container ID (64 hex digits) or nothing.
func sanitizeID(s string) *string {
	if len(s) != 64 {
		return nil
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return nil
		}
	}
	return &s
}
