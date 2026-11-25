package rollout

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/scheduler"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Commander sends a command to a node's agent (agentlink.Hub).
type Commander interface {
	Dispatch(ctx context.Context, nodeID uuid.UUID, cmd *agentv1.Command, timeout time.Duration) (*agentv1.CommandResult, error)
}

// Notes writes to a deployment's log (builds.Logs).
type Notes interface {
	// Note adds a line written by Nook.
	Note(ctx context.Context, deploymentID uuid.UUID, buildID, text string)
	// Output adds lines of the app's own output.
	Output(ctx context.Context, deploymentID uuid.UUID, lines []string)
	End(ctx context.Context, deploymentID uuid.UUID, status store.DeploymentStatus)
}

// Quotas returns a workspace's memory quota in MB (apps.Service).
type Quotas interface {
	MemoryQuotaMB(ctx context.Context, q *store.Queries, workspaceID uuid.UUID) (int64, error)
}

// Deps are the controller's collaborators.
type Deps struct {
	Store     *store.Store
	Commander Commander
	Keyring   *secrets.Keyring
	Issuer    *registry.Issuer
	// RegistryAddr is the registry host:port nodes pull from.
	RegistryAddr string
	Notes        Notes
	Quotas       Quotas
	// Wake asks a deployment's owner to look at it again.
	Wake      func(ctx context.Context, deploymentID uuid.UUID)
	Scheduler scheduler.Config
	Logger    *slog.Logger
}

// Controller releases deployments and keeps them running.
type Controller struct {
	Deps
	cfg Config
	now func() time.Time
}

// New returns a controller.
func New(d *Deps, cfg *Config) *Controller {
	return &Controller{Deps: *d, cfg: *cfg, now: time.Now}
}

// Step moves a built, deploying or live deployment towards its goal and
// reports whether it is done (its owner may stop watching it).
func (c *Controller) Step(ctx context.Context, dep *store.Deployment) (bool, error) {
	app, err := c.Store.GetAppByID(ctx, dep.AppID)
	if err != nil {
		return false, fmt.Errorf("read app: %w", err)
	}
	switch dep.Status {
	case store.DeploymentStatusBuilt:
		return c.stepBuilt(ctx, dep, &app)
	case store.DeploymentStatusDeploying:
		return c.stepDeploying(ctx, dep, &app)
	case store.DeploymentStatusLive:
		return c.converge(ctx, dep, &app)
	default:
		return true, nil
	}
}

// stepBuilt starts the rollout of a built deployment unless it should not
// be released (newer code is live, the app is stopped or deleted).
func (c *Controller) stepBuilt(ctx context.Context, dep *store.Deployment, app *store.App) (bool, error) {
	if app.DeletedAt != nil {
		return c.supersede(ctx, dep, "the app was deleted")
	}
	if dep.Kind == store.DeploymentKindBuild {
		newer, err := c.Store.NewerBuildReleased(ctx, store.NewerBuildReleasedParams{AppID: app.ID, Number: dep.Number})
		if err != nil {
			return false, fmt.Errorf("check newer releases: %w", err)
		}
		if newer {
			return c.supersede(ctx, dep, "a newer deployment is already live")
		}
	}
	if app.DesiredState == store.AppDesiredStateStopped {
		c.Notes.Note(ctx, dep.ID, "", "the app is stopped; this deployment is released when it is started (nook apps start)")
		c.Notes.End(ctx, dep.ID, store.DeploymentStatusBuilt)
		return true, nil
	}
	var started store.Deployment
	err := c.Store.InTx(ctx, func(q *store.Queries) error {
		var snapshot *uuid.UUID
		if dep.EnvSnapshotID == nil {
			s, err := q.CreateEnvSnapshot(ctx, store.CreateEnvSnapshotParams{AppID: app.ID, CreatedBy: dep.CreatedBy})
			if err != nil {
				return fmt.Errorf("create environment snapshot: %w", err)
			}
			if err := q.CopyEnvToSnapshot(ctx, store.CopyEnvToSnapshotParams{SnapshotID: s.ID, AppID: app.ID}); err != nil {
				return fmt.Errorf("copy environment: %w", err)
			}
			snapshot = &s.ID
		}
		var err error
		started, err = q.StartDeploying(ctx, store.StartDeployingParams{ID: dep.ID, EnvSnapshotID: snapshot})
		return err
	})
	switch {
	case store.IsUniqueViolation(err, "deployments_one_deploying_per_app"):
		return false, nil // another release of the app is in progress; wait for it
	case store.IsNotFound(err):
		return false, nil // the status changed; the next step sees it
	case err != nil:
		return false, fmt.Errorf("start rollout: %w", err)
	}
	c.Notes.Note(ctx, dep.ID, "", fmt.Sprintf("releasing deployment #%d", dep.Number))
	return c.stepDeploying(ctx, &started, app)
}

// stepDeploying follows the new instance of a deployment being released.
func (c *Controller) stepDeploying(ctx context.Context, dep *store.Deployment, app *store.App) (bool, error) {
	if app.DeletedAt != nil {
		return c.failRollout(ctx, dep, nil, "the app was deleted")
	}
	inst, err := c.Store.LatestInstanceOfDeployment(ctx, dep.ID)
	if store.IsNotFound(err) {
		created, placeErr := c.place(ctx, dep, app)
		var ae *apperr.Error
		switch {
		case errors.Is(placeErr, scheduler.ErrNoCapacity):
			return c.failRollout(ctx, dep, nil, placeErr.Error())
		case errors.As(placeErr, &ae):
			return c.failRollout(ctx, dep, nil, ae.Message)
		case placeErr != nil:
			return false, placeErr
		}
		c.Notes.Note(ctx, dep.ID, "", "placed on node "+created.NodeName)
		inst = created
	} else if err != nil {
		return false, fmt.Errorf("read instance: %w", err)
	}

	switch inst.State {
	case store.InstanceStateStarting:
		return false, c.followStart(ctx, dep, app, &inst)
	case store.InstanceStateHealthy:
		return c.switchOver(ctx, dep, app, &inst)
	case store.InstanceStateFailed:
		return c.failRollout(ctx, dep, &inst, "the new version did not become healthy: "+orDefault(inst.LastError, "unknown error"))
	case store.InstanceStateUnhealthy:
		return false, nil // the agent is restarting it; wait for the outcome
	default:
		return c.failRollout(ctx, dep, &inst, "the new version stopped before it became healthy")
	}
}

// place records a new instance of dep on a node, within the workspace's
// memory quota. The previous version of the app does not count against
// the quota (both run during the rollout).
func (c *Controller) place(ctx context.Context, dep *store.Deployment, app *store.App) (store.AppInstance, error) {
	var inst store.AppInstance
	err := c.Store.InTx(ctx, func(q *store.Queries) error {
		// Serializes placements in the workspace for the quota check.
		if _, err := q.LockWorkspace(ctx, app.WorkspaceID); err != nil {
			return fmt.Errorf("lock workspace: %w", err)
		}
		quota, err := c.Quotas.MemoryQuotaMB(ctx, q, app.WorkspaceID)
		if err != nil {
			return err
		}
		used, err := q.WorkspaceReservedMemory(ctx, store.WorkspaceReservedMemoryParams{WorkspaceID: app.WorkspaceID, ExceptAppID: app.ID})
		if err != nil {
			return fmt.Errorf("read workspace reservations: %w", err)
		}
		if used+int64(app.MemoryMb) > quota {
			return apperr.Conflict("memory_quota_exceeded",
				"the workspace's memory quota is %d MB; %d MB are reserved by other apps and this app needs %d MB", quota, used, app.MemoryMb)
		}
		inst, err = scheduler.Place(ctx, q, &c.Scheduler, &scheduler.Placement{
			AppID: app.ID, DeploymentID: dep.ID, WorkspaceID: app.WorkspaceID, MemoryMB: app.MemoryMb, Millicores: app.CpuMillicores,
		})
		return err
	})
	return inst, err
}

// followStart sends the start command once and fails an instance whose
// node never reports.
func (c *Controller) followStart(ctx context.Context, dep *store.Deployment, app *store.App, inst *store.AppInstance) error {
	if inst.StartSentAt == nil {
		return c.sendStart(ctx, dep, app, inst)
	}
	limit := c.cfg.PullTimeout + time.Duration(app.StartupTimeoutSeconds)*time.Second + lostGrace
	if c.now().Sub(*inst.StartSentAt) > limit {
		_, err := c.Store.InstanceFailed(ctx, store.InstanceFailedParams{
			ID: inst.ID, LastError: "node " + inst.NodeName + " never reported whether the app started",
		})
		if err != nil && !store.IsNotFound(err) {
			return fmt.Errorf("fail instance: %w", err)
		}
		c.Wake(ctx, dep.ID)
	}
	return nil
}

// switchOver makes a healthy new instance's deployment the live one and
// stops the previous instances after the drain period.
func (c *Controller) switchOver(ctx context.Context, dep *store.Deployment, app *store.App, inst *store.AppInstance) (bool, error) {
	retired := store.DeploymentStatusSuperseded
	if dep.Kind == store.DeploymentKindRollback {
		retired = store.DeploymentStatusRolledBack
	}
	err := c.Store.InTx(ctx, func(q *store.Queries) error {
		if _, err := q.LockApp(ctx, app.ID); err != nil {
			return fmt.Errorf("lock app: %w", err)
		}
		if _, err := q.RetireLive(ctx, store.RetireLiveParams{AppID: app.ID, Status: retired}); err != nil {
			return fmt.Errorf("retire live deployment: %w", err)
		}
		if _, err := q.MarkLive(ctx, dep.ID); err != nil {
			return err
		}
		return q.SetCurrentDeployment(ctx, store.SetCurrentDeploymentParams{ID: app.ID, DeploymentID: &dep.ID})
	})
	if store.IsNotFound(err) {
		return false, nil // no longer deploying; the next step sees why
	}
	if err != nil {
		return false, fmt.Errorf("switch over: %w", err)
	}
	where := inst.NodeName
	if inst.HostPort != nil {
		where = fmt.Sprintf("%s (%s:%d)", inst.NodeName, inst.Address, *inst.HostPort)
	}
	c.Notes.Note(ctx, dep.ID, "", fmt.Sprintf("deployment #%d is live on node %s", dep.Number, where))
	c.Notes.End(ctx, dep.ID, store.DeploymentStatusLive)
	c.stopOthers(ctx, app.ID, dep.ID, c.cfg.Drain)
	return true, nil
}

// stopOthers stops the app's instances that do not belong to keep.
func (c *Controller) stopOthers(ctx context.Context, appID, keep uuid.UUID, drain time.Duration) {
	list, err := c.Store.ListReservedInstancesOfApp(ctx, appID)
	if err != nil {
		c.Logger.WarnContext(ctx, "could not list instances to stop", "app", appID.String(), "error", err.Error())
		return
	}
	for i := range list {
		if list[i].DeploymentID != keep {
			c.stopInstance(ctx, &list[i], drain)
		}
	}
}

// converge keeps a live deployment's instance in the app's desired state.
func (c *Controller) converge(ctx context.Context, dep *store.Deployment, app *store.App) (bool, error) {
	if app.CurrentDeploymentID == nil || *app.CurrentDeploymentID != dep.ID {
		return true, nil
	}
	list, err := c.Store.ListReservedInstancesOfApp(ctx, app.ID)
	if err != nil {
		return false, fmt.Errorf("list instances: %w", err)
	}
	var mine []store.AppInstance
	for i := range list {
		if list[i].DeploymentID == dep.ID {
			mine = append(mine, list[i])
		}
	}
	if app.DeletedAt != nil || app.DesiredState == store.AppDesiredStateStopped {
		for i := range mine {
			if mine[i].State != store.InstanceStateStopping {
				c.stopInstance(ctx, &mine[i], 0)
			}
		}
		return c.stopCrashed(ctx, dep.ID)
	}
	for i := range mine {
		if mine[i].State == store.InstanceStateStarting {
			return false, c.followStart(ctx, dep, app, &mine[i])
		}
		if mine[i].State != store.InstanceStateStopping {
			return true, nil // healthy or restarting: running as wanted
		}
	}
	last, err := c.Store.LatestInstanceOfDeployment(ctx, dep.ID)
	if err == nil && (last.State == store.InstanceStateCrashed || last.State == store.InstanceStateFailed) &&
		!last.CreatedAt.Before(app.DesiredStateAt) {
		return true, nil // it crashed since it was started; a user starts it again
	}
	if err != nil && !store.IsNotFound(err) {
		return false, fmt.Errorf("read instance: %w", err)
	}
	if err == nil && last.State == store.InstanceStateCrashed {
		c.stopInstance(ctx, &last, 0)
	}
	inst, err := c.place(ctx, dep, app)
	var ae *apperr.Error
	if errors.Is(err, scheduler.ErrNoCapacity) || errors.As(err, &ae) {
		// The janitor retries live deployments without an instance.
		c.Logger.WarnContext(ctx, "could not start app", "app", app.Slug, "deployment", dep.ID.String(), "reason", err.Error())
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, c.sendStart(ctx, dep, app, &inst)
}

// stopCrashed removes the container of a crashed instance of a deployment
// that should no longer run (a crashed container is kept for its logs
// while the app is meant to run).
func (c *Controller) stopCrashed(ctx context.Context, depID uuid.UUID) (bool, error) {
	last, err := c.Store.LatestInstanceOfDeployment(ctx, depID)
	if store.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read instance: %w", err)
	}
	if last.State == store.InstanceStateCrashed {
		c.stopInstance(ctx, &last, 0)
	}
	return true, nil
}

func (c *Controller) supersede(ctx context.Context, dep *store.Deployment, reason string) (bool, error) {
	if _, err := c.Store.SupersedeBuilt(ctx, store.SupersedeBuiltParams{ID: dep.ID, Reason: reason}); err != nil && !store.IsNotFound(err) {
		return false, fmt.Errorf("supersede deployment: %w", err)
	}
	c.Notes.Note(ctx, dep.ID, "", "not released: "+reason)
	c.Notes.End(ctx, dep.ID, store.DeploymentStatusSuperseded)
	return true, nil
}

// failRollout ends a release that did not succeed. The previous version
// keeps serving; the failed instance's container is already gone (the
// agent removes it) and its startup output stays on the instance.
func (c *Controller) failRollout(ctx context.Context, dep *store.Deployment, inst *store.AppInstance, reason string) (bool, error) {
	reason = truncate(reason, maxMessage)
	if _, err := c.Store.FailRollout(ctx, store.FailRolloutParams{ID: dep.ID, Reason: reason}); err != nil && !store.IsNotFound(err) {
		return false, fmt.Errorf("fail rollout: %w", err)
	}
	if inst != nil {
		switch inst.State {
		case store.InstanceStateStarting, store.InstanceStateHealthy, store.InstanceStateUnhealthy, store.InstanceStateCrashed:
			c.stopInstance(ctx, inst, 0)
		default:
		}
		if inst.StartupLog != "" {
			c.Notes.Note(ctx, dep.ID, "", "output of the new version before it was stopped:")
			c.Notes.Output(ctx, dep.ID, strings.Split(strings.TrimRight(inst.StartupLog, "\n"), "\n"))
		}
	}
	c.Notes.Note(ctx, dep.ID, "", "release failed: "+reason+"; the previous version keeps serving")
	c.Notes.End(ctx, dep.ID, store.DeploymentStatusFailed)
	return true, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
