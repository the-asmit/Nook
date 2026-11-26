package rollout

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/the-asmit/nook/internal/store"
)

// relocateBatch bounds the instances one relocation pass handles.
const relocateBatch = 500

// retryPlacementEvery is how often a live deployment of a running app
// without an instance (one that failed over or woke while no node had
// room) is handed to its owner again.
const retryPlacementEvery = 10 * time.Second

// FollowUps are what a leader pass does after its database work: commands
// to agents and messages to gateways and owners. They run outside the
// lock connection, which the failure detector shares.
type FollowUps []func(context.Context)

// Run runs the follow-ups.
func (f FollowUps) Run(ctx context.Context) {
	for _, fn := range f {
		fn(ctx)
	}
}

// Relocate moves work off nodes that cannot keep it: instances on dead
// nodes stop counting as running (as of the node's death) and their
// deployments' owners place replacements; deployments with instances on
// draining nodes are handed to their owners, which start a replacement
// and stop the old instance once it is healthy; sleeping apps' kept
// containers on draining nodes are removed (they wake elsewhere);
// failed-over instances whose node is alive again are told to stop (their
// node may never reconnect, so reconciliation would not run); and
// running apps left without an instance for lack of room are retried, so
// they come back as soon as a node returns or frees memory. Every
// change is a compare-and-set, so repeating a pass is harmless. It runs
// on the leader, with db its lock connection; what it decided is carried
// out by the returned follow-ups.
func (c *Controller) Relocate(ctx context.Context, db DB) (FollowUps, error) {
	q := store.New(db)
	var after FollowUps
	dead, err := q.ListInstancesOnDeadNodes(ctx, relocateBatch)
	if err != nil {
		return after, fmt.Errorf("list instances on dead nodes: %w", err)
	}
	for i := range dead {
		d := dead[i]
		deadAt := d.DeadAt
		if _, failErr := q.FailOverInstance(ctx, store.FailOverInstanceParams{ID: d.ID, DeadAt: &deadAt}); failErr != nil {
			if store.IsNotFound(failErr) {
				continue
			}
			return after, fmt.Errorf("fail over instance: %w", failErr)
		}
		after = append(after, func(ctx context.Context) {
			c.Logger.InfoContext(ctx, "failing over an instance from a dead node", "instance", d.ID.String(), "node", d.NodeName,
				"node_dead_for", c.now().Sub(deadAt).Round(time.Millisecond).String())
			c.Routes.Changed(ctx, d.AppID)
			c.kick(ctx, d.DeploymentID)
		})
	}
	back, err := q.ListFailedOverOnLiveNodes(ctx, relocateBatch)
	if err != nil {
		return after, fmt.Errorf("list failed-over instances on live nodes: %w", err)
	}
	for i := range back {
		inst := back[i]
		after = append(after, func(ctx context.Context) {
			c.sendStop(ctx, *inst.NodeID, inst.ID.String(), 0, false)
		})
	}
	moving, err := q.ListDeploymentsOnDrainingNodes(ctx, relocateBatch)
	if err != nil {
		return after, fmt.Errorf("list deployments on draining nodes: %w", err)
	}
	for _, id := range moving {
		after = append(after, func(ctx context.Context) { c.kick(ctx, id) })
	}
	sleepers, err := q.ListSleepingOnDrainingNodes(ctx, relocateBatch)
	if err != nil {
		return after, fmt.Errorf("list sleeping instances on draining nodes: %w", err)
	}
	for i := range sleepers {
		inst, finishErr := q.FinishSleepingInstance(ctx, sleepers[i].ID)
		if store.IsNotFound(finishErr) {
			continue
		}
		if finishErr != nil {
			return after, fmt.Errorf("finish sleeping instance: %w", finishErr)
		}
		after = append(after, func(ctx context.Context) { c.removeKept(ctx, &inst) })
	}
	before := c.now().Add(-retryPlacementEvery)
	stuck, err := q.ListDeploymentsToConverge(ctx, store.ListDeploymentsToConvergeParams{Before: &before, RowLimit: relocateBatch})
	if err != nil {
		return after, fmt.Errorf("list deployments to converge: %w", err)
	}
	for i := range stuck {
		id := stuck[i].ID
		if markErr := q.MarkEnqueued(ctx, id); markErr != nil {
			return after, fmt.Errorf("mark enqueued: %w", markErr)
		}
		after = append(after, func(ctx context.Context) { c.kick(ctx, id) })
	}
	return after, nil
}

// RunLeader runs the leader's loops (failover and draining every
// RelocateInterval, sleeping idle apps every IdleInterval) until ctx
// ends. with supplies the database handle: the leader's lock connection,
// so a deposed leader cannot act (fencing).
func (c *Controller) RunLeader(ctx context.Context, with func(context.Context, func(DB) error) error) {
	relocate := time.NewTicker(c.cfg.RelocateInterval)
	defer relocate.Stop()
	idle := time.NewTicker(c.cfg.IdleInterval)
	defer idle.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-relocate.C:
			var after FollowUps
			err := with(ctx, func(db DB) error {
				var err error
				after, err = c.Relocate(ctx, db)
				return err
			})
			after.Run(ctx)
			if err != nil && ctx.Err() == nil {
				c.Logger.ErrorContext(ctx, "relocation pass failed", "error", err.Error())
			}
		case <-idle.C:
			var after FollowUps
			err := with(ctx, func(db DB) error {
				var err error
				_, after, err = c.SleepIdle(ctx, db, c.now())
				return err
			})
			after.Run(ctx)
			if err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) {
				c.Logger.ErrorContext(ctx, "idle pass failed", "error", err.Error())
			}
		}
	}
}
