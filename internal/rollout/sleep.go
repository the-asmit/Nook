package rollout

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"

	"github.com/the-asmit/nook/internal/activity"
	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/scheduler"
	"github.com/the-asmit/nook/internal/store"
)

// Why instances stop (app_instances.stop_reason).
const (
	stopReplaced = "replaced"
	stopStopped  = "stopped"
	stopDeleted  = "deleted"
	stopSleep    = "sleep"
	stopFailover = "failover"
	stopDrain    = "drain"
)

// DB is a database handle the leader's loops run on (its lock connection,
// for fencing) or a pool in tests.
type DB interface {
	store.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

// SleepDue reports whether an app last used at last, sleeping after
// `after` without requests, should be asleep at now.
func SleepDue(last time.Time, after time.Duration, now time.Time) bool {
	return !now.Before(last.Add(after))
}

// SleepIdle puts to sleep every running app idle for at least its
// sleep_after at now. It runs on the leader, with db its lock connection;
// it returns how many apps it put to sleep, and the follow-ups that stop
// their containers.
func (c *Controller) SleepIdle(ctx context.Context, db DB, now time.Time) (int, FollowUps, error) {
	q := store.New(db)
	var after FollowUps
	cands, err := q.ListIdleCandidates(ctx)
	if err != nil {
		return 0, after, fmt.Errorf("list idle candidates: %w", err)
	}
	if len(cands) == 0 {
		return 0, after, nil
	}
	act, err := c.Activity(ctx)
	if err != nil {
		return 0, after, err
	}
	slept := 0
	for i := range cands {
		cand := cands[i]
		if cand.SleepAfterSeconds == nil || cand.CurrentDeploymentID == nil {
			continue
		}
		last := activity.Latest(act, cand.AppID, cand.LastRequestAt, cand.LastHealthyAt)
		if !SleepDue(last, time.Duration(*cand.SleepAfterSeconds)*time.Second, now) {
			continue
		}
		inst, err := sleepTx(ctx, db, cand.AppID, *cand.CurrentDeploymentID, cand.InstanceID, scheduler.SleepIdle, last)
		if errors.Is(err, errNotAsleep) {
			continue // woken, stopped or redeployed meanwhile
		}
		if err != nil {
			return slept, after, err
		}
		slept++
		after = append(after, func(ctx context.Context) {
			c.metrics.sleeps.WithLabelValues(scheduler.SleepIdle).Inc()
			c.Logger.InfoContext(ctx, "app went to sleep", "app", cand.Slug, "app_id", cand.AppID.String(),
				"idle", now.Sub(last).Round(time.Second).String(), "memory_mb", inst.MemoryMb)
			c.afterSleep(ctx, &inst)
		})
	}
	return slept, after, nil
}

// errNotAsleep means the app changed before it could be put to sleep.
var errNotAsleep = errors.New("the app could not be put to sleep")

// sleepTx marks the app sleeping and its instance sleeping (reservation
// released) in one transaction on db.
func sleepTx(ctx context.Context, db DB, appID, deploymentID, instanceID uuid.UUID, reason string, last time.Time) (store.AppInstance, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return store.AppInstance{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := store.New(tx)
	if _, err = q.SleepApp(ctx, store.SleepAppParams{ID: appID, Reason: reason, LastRequestAt: &last, DeploymentID: &deploymentID}); err != nil {
		if store.IsNotFound(err) {
			return store.AppInstance{}, errNotAsleep
		}
		return store.AppInstance{}, fmt.Errorf("put app to sleep: %w", err)
	}
	inst, err := q.SleepInstance(ctx, store.SleepInstanceParams{ID: instanceID, StopReason: stopSleep})
	if err != nil {
		if store.IsNotFound(err) {
			return store.AppInstance{}, errNotAsleep
		}
		return store.AppInstance{}, fmt.Errorf("put instance to sleep: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return store.AppInstance{}, fmt.Errorf("commit sleep: %w", err)
	}
	return inst, nil
}

// afterSleep stops a sleeping instance's container (keeping it for a fast
// wake on the same node) and tells the gateways. A node that cannot be
// reached stops it when its agent reconnects (reconciliation).
func (c *Controller) afterSleep(ctx context.Context, inst *store.AppInstance) {
	c.Routes.Changed(ctx, inst.AppID)
	if inst.NodeID == nil || c.nodeRemoved(ctx, *inst.NodeID) {
		return
	}
	c.sendStop(ctx, *inst.NodeID, inst.ID.String(), 0, true)
}

// finishSleeping ends a sleeping instance that will not wake on its node
// (the app woke elsewhere, was redeployed, stopped or deleted): its kept
// container is removed.
func (c *Controller) finishSleeping(ctx context.Context, inst *store.AppInstance) {
	if _, err := c.Store.FinishSleepingInstance(ctx, inst.ID); err != nil {
		if !store.IsNotFound(err) {
			c.Logger.WarnContext(ctx, "could not finish a sleeping instance", "instance", inst.ID.String(), "error", err.Error())
		}
		return
	}
	c.removeKept(ctx, inst)
}

// removeKept asks the node of a finished sleeping instance to remove its
// kept container (an unreachable node does it when its agent reconnects:
// the instance is no longer one it should have).
func (c *Controller) removeKept(ctx context.Context, inst *store.AppInstance) {
	if inst.NodeID != nil && !c.nodeRemoved(ctx, *inst.NodeID) {
		c.sendStop(ctx, *inst.NodeID, inst.ID.String(), 0, false)
	}
}

// failOver marks an instance on a dead node as no longer serving, stopped
// as of the node's death (which the failover time is measured from). Its
// container is removed if the node comes back (reconciliation); the
// gateways never route to it again.
func (c *Controller) failOver(ctx context.Context, inst *store.AppInstance) {
	deadAt := c.now()
	if inst.NodeID != nil {
		if t, err := c.Store.NodeDeadAt(ctx, *inst.NodeID); err == nil {
			deadAt = t
		}
	}
	if _, err := c.Store.FailOverInstance(ctx, store.FailOverInstanceParams{ID: inst.ID, DeadAt: &deadAt}); err != nil {
		if !store.IsNotFound(err) {
			c.Logger.WarnContext(ctx, "could not fail over an instance", "instance", inst.ID.String(), "error", err.Error())
		}
		return
	}
	c.Logger.InfoContext(ctx, "failing over an instance from a dead node", "instance", inst.ID.String(), "node", inst.NodeName)
	c.Routes.Changed(ctx, inst.AppID)
}

// WakeState is what a wake request found.
type WakeState string

// Wake outcomes.
const (
	// WakeStarted: this request woke the app (the one compare-and-set
	// that wins); its instance is being started.
	WakeStarted WakeState = "waking"
	// WakeAlready: someone else woke it, or it was awake.
	WakeAlready WakeState = "awake"
)

// WakeApp wakes a sleeping app. However many gateways and requests call
// it at once, exactly one wins the compare-and-set and hands the live
// deployment to its owner, which starts one instance (resumed on its node
// when there is room).
func (c *Controller) WakeApp(ctx context.Context, appID uuid.UUID) (WakeState, error) {
	app, err := c.Store.WakeApp(ctx, appID)
	if store.IsNotFound(err) {
		current, getErr := c.Store.GetAppByID(ctx, appID)
		if store.IsNotFound(getErr) || (getErr == nil && current.DeletedAt != nil) {
			return "", apperr.NotFound("app not found")
		}
		if getErr != nil {
			return "", fmt.Errorf("read app: %w", getErr)
		}
		return WakeAlready, nil
	}
	if err != nil {
		return "", fmt.Errorf("wake app: %w", err)
	}
	c.metrics.wakes.Inc()
	c.Logger.InfoContext(ctx, "waking app", "app", app.Slug, "app_id", app.ID.String())
	c.Routes.Changed(ctx, app.ID)
	if app.CurrentDeploymentID != nil {
		c.kick(ctx, *app.CurrentDeploymentID)
	}
	return WakeStarted, nil
}

// kick hands a deployment to its owner now (enqueueing it if nobody owns
// it; a duplicate job is dropped by the dispatcher).
func (c *Controller) kick(ctx context.Context, deploymentID uuid.UUID) {
	if err := c.Enqueue(ctx, deploymentID); err != nil {
		c.Logger.WarnContext(ctx, "could not enqueue a deployment; the janitor retries", "deployment", deploymentID.String(), "error", err.Error())
	}
	c.Wake(ctx, deploymentID)
}

// recovered records the first healthy report of an instance that replaced
// a sleeping, dead or drained one: wake and failover times, from the wake
// request or the node's death to healthy (both on the database's clock).
func (c *Controller) recovered(ctx context.Context, inst *store.AppInstance) {
	if inst.CauseAt == nil || inst.LastHealthyAt == nil {
		return
	}
	took := inst.LastHealthyAt.Sub(*inst.CauseAt)
	switch inst.Cause {
	case scheduler.CauseWake:
		c.metrics.wake.Observe(took.Seconds())
		if err := c.Store.WakeDone(ctx, inst.AppID); err != nil {
			c.Logger.WarnContext(ctx, "could not record a finished wake", "app_id", inst.AppID.String(), "error", err.Error())
		}
		c.Logger.InfoContext(ctx, "app woke", "app_id", inst.AppID.String(), "node", inst.NodeName, "took", took.String())
	case scheduler.CauseFailover:
		c.metrics.failover.Observe(took.Seconds())
		c.Logger.InfoContext(ctx, "app failed over", "app_id", inst.AppID.String(), "node", inst.NodeName,
			"since_node_died", took.Round(time.Millisecond).String())
	case scheduler.CauseDrain:
		c.metrics.moved.Observe(took.Seconds())
	default:
	}
}
