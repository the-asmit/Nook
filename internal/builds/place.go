package builds

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"time"
	"uuid"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// candidate is a node that could take a build.
type candidate struct {
	id         uuid.UUID
	name       string
	freeMemory int64
	triedHere  bool
}

// pickNode chooses a node for a deployment: ready, not draining, with a
// free build slot; nodes that already failed this deployment last;
// otherwise the most free memory first.
func (d *Dispatcher) pickNode(ctx context.Context, depID uuid.UUID) (*candidate, error) {
	rows, err := d.Store.ListBuildNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list build nodes: %w", err)
	}
	active, err := d.Store.CountActiveBuildsByNode(ctx)
	if err != nil {
		return nil, fmt.Errorf("count builds per node: %w", err)
	}
	busy := map[uuid.UUID]int32{}
	for _, a := range active {
		if a.NodeID != nil {
			busy[*a.NodeID] = a.Active
		}
	}
	tried, err := d.Store.NodesTriedForDeployment(ctx, depID)
	if err != nil {
		return nil, fmt.Errorf("list tried nodes: %w", err)
	}
	var cands []candidate
	for _, n := range rows {
		if busy[n.ID] >= n.BuildSlots {
			continue
		}
		c := candidate{id: n.ID, name: n.Name, triedHere: slices.ContainsFunc(tried, func(t *uuid.UUID) bool { return t != nil && *t == n.ID })}
		if n.MemoryAvailableBytes != nil {
			c.freeMemory = *n.MemoryAvailableBytes
		}
		if hb, err := d.Heartbeats.LatestHeartbeat(ctx, n.ID); err == nil && hb != nil {
			c.freeMemory = hb.MemoryAvailableBytes
		}
		cands = append(cands, c)
	}
	if len(cands) == 0 {
		return nil, nil
	}
	slices.SortFunc(cands, func(a, b candidate) int {
		if a.triedHere != b.triedHere {
			if a.triedHere {
				return 1
			}
			return -1
		}
		switch {
		case a.freeMemory > b.freeMemory:
			return -1
		case a.freeMemory < b.freeMemory:
			return 1
		}
		return 0
	})
	return &cands[0], nil
}

// place starts the next attempt of a queued deployment if the app has no
// other build running, the workspace is under its concurrent-build quota
// and a node has room. Otherwise the deployment keeps waiting.
func (d *Dispatcher) place(ctx context.Context, dep *store.Deployment, app *store.App) error {
	quota, err := d.Apps.QuotaFor(ctx, d.Store.Queries, app.WorkspaceID)
	if err != nil {
		return err
	}
	running, err := d.Store.CountActiveBuildsInWorkspace(ctx, app.WorkspaceID)
	if err != nil {
		return fmt.Errorf("count workspace builds: %w", err)
	}
	if running >= quota.MaxConcurrentBuilds {
		return nil
	}
	node, err := d.pickNode(ctx, dep.ID)
	if err != nil || node == nil {
		return err
	}
	attempt := int32(1)
	if last, lastErr := d.Store.LastBuild(ctx, dep.ID); lastErr == nil {
		attempt = last.Attempt + 1
	} else if !store.IsNotFound(lastErr) {
		return fmt.Errorf("read last build: %w", lastErr)
	}

	var b store.Build
	err = d.Store.InTx(ctx, func(q *store.Queries) error {
		if _, startErr := q.StartBuilding(ctx, dep.ID); startErr != nil {
			return startErr
		}
		buildID := uuid.NewV7()
		var createErr error
		b, createErr = q.CreateBuild(ctx, store.CreateBuildParams{
			DeploymentID: dep.ID, AppID: app.ID, WorkspaceID: app.WorkspaceID, NodeID: &node.id, NodeName: node.name,
			Attempt: attempt, ImageTag: "b-" + buildID.String(),
		})
		return createErr
	})
	switch {
	case store.IsNotFound(err):
		return nil // no longer queued
	case store.IsUniqueViolation(err, "builds_one_active_per_app"):
		return nil // another deployment of the app is building; wait
	case store.IsUniqueViolation(err, "builds_one_active_per_deployment"), store.IsUniqueViolation(err, "builds_deployment_attempt_key"):
		return nil // someone else placed it
	case err != nil:
		return fmt.Errorf("start build: %w", err)
	}
	// A registry maintenance window may have opened after the check in
	// stepQueued; it waits for builds that exist, so withdraw this one.
	if paused, err := gcWindowActive(ctx, d.Redis); err != nil || paused {
		return d.withdraw(ctx, dep, &b)
	}
	d.metrics.dispatched.Inc()
	if dep.QueuedAt != nil {
		d.metrics.queueWait.Observe(time.Since(*dep.QueuedAt).Seconds())
	}
	d.Logs.Note(ctx, dep.ID, b.ID.String(), fmt.Sprintf("attempt %d on node %s", attempt, node.name))
	return d.send(ctx, dep, app, &b, node)
}

// send hands the build to the node's agent. A node that cannot take it
// fails the attempt as an infrastructure error, which is retried.
func (d *Dispatcher) send(ctx context.Context, dep *store.Deployment, app *store.App, b *store.Build, node *candidate) error {
	repo := apps.RepositoryName(app.WorkspaceID, app.ID)
	cacheRepo := apps.CacheRepositoryName(app.WorkspaceID, app.ID)
	token, err := d.Issuer.Token("node:"+node.name, d.cfg.Timeout+tokenMargin,
		registry.RepositoryAccess(repo, registry.ActionPush, registry.ActionPull),
		registry.RepositoryAccess(cacheRepo, registry.ActionPush, registry.ActionPull))
	if err != nil {
		return err
	}
	cmd := &agentv1.Command{Kind: &agentv1.Command_Build{Build: &agentv1.BuildCommand{
		BuildId: b.ID.String(), DeploymentId: dep.ID.String(), Attempt: b.Attempt,
		SourceUrl:    d.Objects.PresignGet(dep.SourceKey, d.cfg.Timeout+tokenMargin),
		SourceSha256: hex.EncodeToString(dep.SourceSha256), SourceSize: dep.SourceSize,
		Registry: d.RegistryAddr, Repository: repo, Tag: b.ImageTag, RegistryToken: token, CacheRepository: cacheRepo,
		Timeout: durationpb.New(d.cfg.Timeout), MemoryBytes: d.cfg.MemoryMB << 20, CpuMillicores: d.cfg.CPUMillicores,
		MaxLogBytes: d.cfg.MaxLogBytes,
	}}}
	res, err := d.Commander.Dispatch(ctx, node.id, cmd, dispatchTimeout)
	if err == nil && res.GetError() == nil {
		if _, err := d.Store.MarkBuildStarted(ctx, b.ID); err != nil && !store.IsNotFound(err) {
			return fmt.Errorf("mark build started: %w", err)
		}
		return nil
	}
	reason := "node " + node.name + " could not take the build"
	if res.GetError() != nil {
		reason += ": " + res.GetError().GetMessage()
	}
	infra := store.BuildResultInfraError
	if _, ferr := d.Store.FinishBuild(ctx, store.FinishBuildParams{ID: b.ID, Result: &infra, Message: reason}); ferr == nil {
		d.metrics.finished.WithLabelValues(string(infra)).Inc()
		d.Logs.Note(ctx, dep.ID, b.ID.String(), reason)
	}
	return nil
}

// withdraw undoes the placement of a build that was never sent.
func (d *Dispatcher) withdraw(ctx context.Context, dep *store.Deployment, b *store.Build) error {
	return d.Store.InTx(ctx, func(q *store.Queries) error {
		n, err := q.DeleteUnstartedBuild(ctx, b.ID)
		if err != nil || n == 0 {
			return err
		}
		if _, err := q.RequeueDeployment(ctx, dep.ID); err != nil && !store.IsNotFound(err) {
			return err
		}
		return nil
	})
}

// failureReason is the user-facing reason of a failed attempt.
func failureReason(b *store.Build) string {
	if b.Message != "" {
		return b.Message
	}
	return "the build failed"
}
