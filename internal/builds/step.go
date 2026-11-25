package builds

import (
	"context"
	"fmt"
	"strconv"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// step moves one deployment forward and reports whether it is finished
// (its job can be acknowledged). Every transition is a compare-and-set
// in Postgres, so racing owners, retries and redeliveries cannot produce a
// second build or a second outcome.
func (d *Dispatcher) step(ctx context.Context, id uuid.UUID) (bool, error) {
	dep, err := d.Store.GetDeploymentByID(ctx, id)
	if store.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read deployment: %w", err)
	}
	switch dep.Status {
	case store.DeploymentStatusQueued:
		return d.stepQueued(ctx, &dep)
	case store.DeploymentStatusBuilding:
		return d.stepBuilding(ctx, &dep)
	case store.DeploymentStatusBuilt, store.DeploymentStatusDeploying, store.DeploymentStatusLive:
		return d.Releases.Step(ctx, &dep)
	default:
		// Finished, or not yet uploaded (a stale job): nothing to do.
		return true, nil
	}
}

func (d *Dispatcher) stepQueued(ctx context.Context, dep *store.Deployment) (bool, error) {
	app, err := d.Store.GetAppByID(ctx, dep.AppID)
	if err != nil {
		return false, fmt.Errorf("read app: %w", err)
	}
	if app.DeletedAt != nil {
		return d.cancel(ctx, dep, "the app was deleted")
	}
	if dep.CancelRequestedAt != nil {
		return d.cancel(ctx, dep, "canceled by a user")
	}
	if dep.QueuedAt != nil && time.Since(*dep.QueuedAt) > d.cfg.QueueTimeout {
		return d.fail(ctx, dep, fmt.Sprintf("no build capacity: no node could build this deployment within %s", d.cfg.QueueTimeout))
	}
	if paused, err := gcWindowActive(ctx, d.Redis); err != nil || paused {
		return false, err
	}
	return false, d.place(ctx, dep, &app)
}

func (d *Dispatcher) stepBuilding(ctx context.Context, dep *store.Deployment) (bool, error) {
	b, err := d.Store.GetActiveBuild(ctx, dep.ID)
	if store.IsNotFound(err) {
		return d.afterAttempt(ctx, dep)
	}
	if err != nil {
		return false, fmt.Errorf("read build: %w", err)
	}
	if dep.CancelRequestedAt != nil {
		return false, d.stopBuild(ctx, dep, &b)
	}
	if reason := d.lostReason(ctx, &b); reason != "" {
		d.finishLost(ctx, dep, &b, reason)
	}
	return false, nil
}

// lostReason explains why an unfinished build will never report, or
// returns "" while it may still.
func (d *Dispatcher) lostReason(ctx context.Context, b *store.Build) string {
	if b.NodeID == nil {
		return "its node was removed"
	}
	status, err := d.Store.GetNodeStatus(ctx, *b.NodeID)
	switch {
	case store.IsNotFound(err) || status == store.NodeStatusRemoved:
		return "its node was removed"
	case err != nil:
		return ""
	case status == store.NodeStatusDead:
		return "node " + b.NodeName + " stopped responding"
	case b.StartedAt == nil && time.Since(b.DispatchedAt) > d.cfg.AcceptTimeout:
		return "node " + b.NodeName + " never started it"
	case time.Since(b.DispatchedAt) > d.cfg.Timeout+resultGrace:
		return "node " + b.NodeName + " never reported a result"
	}
	return ""
}

func (d *Dispatcher) finishLost(ctx context.Context, dep *store.Deployment, b *store.Build, reason string) {
	lost := store.BuildResultLost
	fin, err := d.Store.FinishBuild(ctx, store.FinishBuildParams{ID: b.ID, Result: &lost, Message: "lost: " + reason})
	if err != nil {
		return // already finished by a result that just arrived
	}
	d.metrics.finished.WithLabelValues(string(lost)).Inc()
	d.Logs.Note(ctx, dep.ID, b.ID.String(), "attempt "+itoa(b.Attempt)+" was lost: "+reason)
	d.persistLog(ctx, dep, &fin)
}

// afterAttempt decides what follows a finished attempt of a deployment
// that is still building: another attempt (after an infrastructure
// failure) or giving up.
func (d *Dispatcher) afterAttempt(ctx context.Context, dep *store.Deployment) (bool, error) {
	last, err := d.Store.LastBuild(ctx, dep.ID)
	if err != nil {
		return false, fmt.Errorf("read last build: %w", err)
	}
	if last.Result == nil || (*last.Result != store.BuildResultInfraError && *last.Result != store.BuildResultLost) {
		// The result handler records final outcomes together with the
		// build; seeing one here means a crash between them: finish now.
		return d.finalizeFrom(ctx, dep, &last)
	}
	if dep.CancelRequestedAt != nil {
		return d.cancel(ctx, dep, "canceled by a user")
	}
	if last.Attempt >= d.cfg.MaxAttempts {
		return d.fail(ctx, dep, fmt.Sprintf("the build could not run: %d attempts failed for reasons outside the build (last: %s)", last.Attempt, last.Message))
	}
	if _, err := d.Store.RequeueDeployment(ctx, dep.ID); err != nil && !store.IsNotFound(err) {
		return false, fmt.Errorf("requeue deployment: %w", err)
	}
	d.Logs.Note(ctx, dep.ID, "", "retrying on another node")
	return false, nil
}

func (d *Dispatcher) finalizeFrom(ctx context.Context, dep *store.Deployment, b *store.Build) (bool, error) {
	var err error
	switch {
	case b.Result != nil && *b.Result == store.BuildResultSucceeded && b.ImageDigest != nil:
		_, err = d.Store.MarkBuilt(ctx, store.MarkBuiltParams{ID: dep.ID, ImageDigest: b.ImageDigest})
	case b.Result != nil && *b.Result == store.BuildResultCancelled:
		_, err = d.Store.MarkCancelled(ctx, store.MarkCancelledParams{ID: dep.ID, Reason: "canceled"})
	default:
		_, err = d.Store.MarkFailed(ctx, store.MarkFailedParams{ID: dep.ID, Reason: failureReason(b)})
	}
	if err != nil && !store.IsNotFound(err) {
		return false, fmt.Errorf("finish deployment: %w", err)
	}
	if b.Result != nil && *b.Result == store.BuildResultSucceeded {
		return false, nil // the next step releases it
	}
	d.ended(ctx, dep.ID)
	return true, nil
}

// stopBuild asks the agent to cancel a running build and records the
// cancellation if the agent cannot confirm it.
func (d *Dispatcher) stopBuild(ctx context.Context, dep *store.Deployment, b *store.Build) error {
	if b.CancelSentAt == nil && b.NodeID != nil {
		if err := d.Store.MarkCancelSent(ctx, b.ID); err != nil {
			return fmt.Errorf("mark cancel sent: %w", err)
		}
		res, err := d.Commander.Dispatch(ctx, *b.NodeID, &agentv1.Command{Kind: &agentv1.Command_CancelBuild{
			CancelBuild: &agentv1.CancelBuildCommand{BuildId: b.ID.String()}}}, dispatchTimeout)
		if err == nil && res.GetError() == nil {
			d.Logs.Note(ctx, dep.ID, b.ID.String(), "canceling the build")
			return nil
		}
	} else if b.CancelSentAt != nil && time.Since(*b.CancelSentAt) < cancelGrace {
		return nil
	}
	// The agent is unreachable or did not confirm in time.
	canceled := store.BuildResultCancelled
	if _, err := d.Store.FinishBuild(ctx, store.FinishBuildParams{ID: b.ID, Result: &canceled, Message: "canceled"}); err == nil {
		d.metrics.finished.WithLabelValues(string(canceled)).Inc()
		_, err := d.cancel(ctx, dep, "canceled by a user")
		return err
	}
	return nil
}

func (d *Dispatcher) cancel(ctx context.Context, dep *store.Deployment, reason string) (bool, error) {
	if _, err := d.Store.MarkCancelled(ctx, store.MarkCancelledParams{ID: dep.ID, Reason: reason}); err != nil && !store.IsNotFound(err) {
		return false, fmt.Errorf("cancel deployment: %w", err)
	}
	d.Logs.Note(ctx, dep.ID, "", "deployment canceled: "+reason)
	d.ended(ctx, dep.ID)
	return true, nil
}

func (d *Dispatcher) fail(ctx context.Context, dep *store.Deployment, reason string) (bool, error) {
	if _, err := d.Store.MarkFailed(ctx, store.MarkFailedParams{ID: dep.ID, Reason: reason}); err != nil && !store.IsNotFound(err) {
		return false, fmt.Errorf("fail deployment: %w", err)
	}
	d.Logs.Note(ctx, dep.ID, "", "deployment failed: "+reason)
	d.ended(ctx, dep.ID)
	return true, nil
}

// ended closes the deployment's live log with its final status.
func (d *Dispatcher) ended(ctx context.Context, id uuid.UUID) {
	dep, err := d.Store.GetDeploymentByID(ctx, id)
	if err != nil {
		return
	}
	d.Logs.End(ctx, id, dep.Status)
}

func (d *Dispatcher) persistLog(ctx context.Context, dep *store.Deployment, b *store.Build) {
	app, err := d.Store.GetAppByID(ctx, dep.AppID)
	if err != nil {
		return
	}
	if err := d.Logs.Persist(ctx, app.WorkspaceID, b); err != nil {
		d.Logger.WarnContext(ctx, "could not store build log", "build", b.ID.String(), "error", err.Error())
	}
}

func itoa(n int32) string { return strconv.Itoa(int(n)) }
