package rollout

// Placing instances and converging live deployments: releases, restarts,
// wakes, failover and drain replacements all place through here.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/scheduler"
	"github.com/the-asmit/nook/internal/store"
)

// placeOpts are why an instance is placed and whether a sleeping one may
// resume in place.
type placeOpts struct {
	cause   string
	causeAt *time.Time
	resume  *store.AppInstance
}

// place records an instance of dep on a node, within the workspace's
// memory quota, resuming a sleeping instance on its node or evicting idle
// apps when that is what makes room. The previous version of the app does
// not count against the quota (both run during the rollout). Evictions
// are audited in the same transaction; their containers are stopped
// (kept) after it commits.
func (c *Controller) place(ctx context.Context, dep *store.Deployment, app *store.App, o *placeOpts) (scheduler.Result, error) {
	var evict *scheduler.Eviction
	if act, err := c.Activity(ctx); err != nil {
		c.Logger.WarnContext(ctx, "app activity unavailable; placing without eviction", "error", err.Error())
	} else {
		evict = &scheduler.Eviction{Activity: act, Now: c.now()}
	}
	var res scheduler.Result
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
		res, err = scheduler.Place(ctx, q, &c.Scheduler, &scheduler.Placement{
			AppID: app.ID, DeploymentID: dep.ID, WorkspaceID: app.WorkspaceID, MemoryMB: app.MemoryMb, Millicores: app.CpuMillicores,
			Cause: o.cause, CauseAt: o.causeAt, Resume: o.resume, Evict: evict,
		})
		if err != nil {
			return err
		}
		for i := range res.Evicted {
			ev := &res.Evicted[i]
			if err := audit.Record(ctx, q, &audit.Entry{
				WorkspaceID: &ev.App.WorkspaceID, Action: audit.ActionAppEvict, TargetType: "app", TargetID: ev.App.ID.String(),
				Metadata: map[string]any{
					"slug": ev.App.Slug, "node": res.Instance.NodeName, "for_app": app.ID.String(),
					"idle_seconds": int64(c.now().Sub(ev.LastActive).Seconds()),
				},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return scheduler.Result{}, err
	}
	for i := range res.Evicted {
		ev := &res.Evicted[i]
		c.Logger.InfoContext(ctx, "evicted an idle app to make room", "app", ev.App.Slug, "app_id", ev.App.ID.String(),
			"node", res.Instance.NodeName, "for_app", app.Slug, "idle", c.now().Sub(ev.LastActive).Round(time.Second).String())
		c.metrics.sleeps.WithLabelValues(scheduler.SleepEvicted).Inc()
		c.afterSleep(ctx, &ev.Instance)
	}
	return res, nil
}

// converge keeps a live deployment's instance in the app's desired state:
// stopped, asleep, or running on a usable node. An instance on a draining
// node is replaced first (the old one serves until the new one is
// healthy); one on a dead node is failed over; an app without a running
// instance gets one, resuming its sleeping instance in place when its node
// has room.
func (c *Controller) converge(ctx context.Context, dep *store.Deployment, app *store.App) (bool, error) {
	if app.CurrentDeploymentID == nil || *app.CurrentDeploymentID != dep.ID {
		return true, nil
	}
	rows, err := c.Store.ListDeploymentInstances(ctx, dep.ID)
	if err != nil {
		return false, fmt.Errorf("list instances: %w", err)
	}
	var active, reserved []*store.ListDeploymentInstancesRow
	var sleeping *store.AppInstance
	for i := range rows {
		r := &rows[i]
		switch r.AppInstance.State {
		case store.InstanceStateStarting, store.InstanceStateHealthy, store.InstanceStateUnhealthy:
			active = append(active, r)
			reserved = append(reserved, r)
		case store.InstanceStateStopping:
			reserved = append(reserved, r)
		case store.InstanceStateSleeping:
			sleeping = &r.AppInstance
		default:
		}
	}
	if app.DeletedAt != nil || app.DesiredState == store.AppDesiredStateStopped {
		// Instances already stopping get the request again: the first one
		// may have been lost (stopping is idempotent on the agent).
		reason := stopStopped
		if app.DeletedAt != nil {
			reason = stopDeleted
		}
		for _, r := range reserved {
			c.stopInstance(ctx, &r.AppInstance, 0, reason)
		}
		if sleeping != nil {
			c.finishSleeping(ctx, sleeping)
		}
		return c.stopCrashed(ctx, dep.ID)
	}
	if app.SleepingSince != nil {
		// Put to sleep while an instance was still starting: it sleeps too.
		for _, r := range active {
			if inst, sleepErr := c.Store.SleepInstance(ctx, store.SleepInstanceParams{ID: r.AppInstance.ID, StopReason: stopSleep}); sleepErr == nil {
				c.afterSleep(ctx, &inst)
			}
		}
		return true, nil
	}
	var good, moving []*store.ListDeploymentInstancesRow
	for _, r := range active {
		switch {
		case r.NodeStatus == string(store.NodeStatusDead):
			c.failOver(ctx, &r.AppInstance)
		case r.AppInstance.State == store.InstanceStateStarting:
			return false, c.followStart(ctx, dep, app, &r.AppInstance)
		case r.NodeDraining || r.NodeStatus == string(store.NodeStatusRemoved) || r.AppInstance.NodeID == nil:
			moving = append(moving, r)
		default:
			good = append(good, r)
		}
	}
	if len(good) > 0 {
		// Running where it should: the newest healthy instance serves; any
		// other (the one on a draining node, once its replacement is
		// healthy) stops after the drain period.
		keep := good[len(good)-1]
		for _, r := range active {
			if r != keep && r.NodeStatus != string(store.NodeStatusDead) {
				reason := stopReplaced
				if r.NodeDraining {
					reason = stopDrain
				}
				c.stopInstance(ctx, &r.AppInstance, c.cfg.Drain, reason)
			}
		}
		if sleeping != nil {
			c.finishSleeping(ctx, sleeping)
		}
		return true, nil
	}
	if len(moving) > 0 {
		// Only on a draining node: start a replacement elsewhere; the old
		// instance keeps serving until it is healthy.
		now := c.now()
		return c.startReplacement(ctx, dep, app, &placeOpts{cause: scheduler.CauseDrain, causeAt: &now})
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
		c.stopInstance(ctx, &last, 0, stopReplaced)
	}
	o := c.restartCause(ctx, dep, app)
	o.resume = sleeping
	return c.startReplacement(ctx, dep, app, o)
}

// startReplacement places a new instance of dep (or resumes its sleeping
// one) and starts it.
func (c *Controller) startReplacement(ctx context.Context, dep *store.Deployment, app *store.App, o *placeOpts) (bool, error) {
	res, err := c.place(ctx, dep, app, o)
	var ae *apperr.Error
	switch {
	case errors.Is(err, scheduler.ErrNoCapacity) || errors.As(err, &ae):
		// The janitor retries live deployments without an instance.
		c.Logger.WarnContext(ctx, "could not start app", "app", app.Slug, "deployment", dep.ID.String(), "reason", err.Error())
		return true, nil
	case store.IsUniqueViolation(err, "app_instances_one_starting_per_deployment"):
		return false, nil // another owner started one; follow it next time
	case err != nil:
		return false, err
	}
	if !res.Resumed && o.resume != nil {
		c.finishSleeping(ctx, o.resume)
	}
	return false, c.sendStart(ctx, dep, app, &res.Instance)
}

// restartCause tells why a live deployment without a running instance needs
// one: a wake request, its node's death, or a restart (the app was
// started, or its instance vanished).
func (c *Controller) restartCause(ctx context.Context, dep *store.Deployment, app *store.App) *placeOpts {
	if app.WakeRequestedAt != nil {
		return &placeOpts{cause: scheduler.CauseWake, causeAt: app.WakeRequestedAt}
	}
	if last, err := c.Store.LatestStoppedInstanceOfDeployment(ctx, dep.ID); err == nil && last.StopReason == stopFailover {
		return &placeOpts{cause: scheduler.CauseFailover, causeAt: last.StopRequestedAt}
	}
	return &placeOpts{cause: scheduler.CauseRestart}
}
