package builds

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"uuid"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/registry"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Bounds on what an agent may report in one message.
const (
	maxLinesPerMessage = 1000
	maxLineLength      = 8192
	maxMessageLength   = 500
)

// errNotYours means a node reported on a build it was not given.
var errNotYours = errors.New("the build does not belong to this node")

// buildFor loads a build an agent reports on and checks it is the
// reporting node's.
func (d *Dispatcher) buildFor(ctx context.Context, nodeID uuid.UUID, rawID string) (store.Build, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return store.Build{}, errNotYours
	}
	b, err := d.Store.GetBuild(ctx, id)
	if store.IsNotFound(err) {
		return store.Build{}, errNotYours
	}
	if err != nil {
		return store.Build{}, fmt.Errorf("read build: %w", err)
	}
	if b.NodeID == nil || *b.NodeID != nodeID {
		return store.Build{}, errNotYours
	}
	return b, nil
}

// BuildLog records output an agent reported for one of its builds.
// Output for builds that already ended (for example after being declared
// lost) is dropped.
func (d *Dispatcher) BuildLog(ctx context.Context, nodeID uuid.UUID, m *agentv1.BuildLog) error {
	b, err := d.buildFor(ctx, nodeID, m.GetBuildId())
	if errors.Is(err, errNotYours) {
		return nil
	}
	if err != nil || b.FinishedAt != nil {
		return err
	}
	lines := m.GetLines()
	if len(lines) > maxLinesPerMessage {
		lines = lines[:maxLinesPerMessage]
	}
	clean := make([]string, len(lines))
	for i, l := range lines {
		if len(l) > maxLineLength {
			l = l[:maxLineLength]
		}
		clean[i] = strings.ToValidUTF8(l, "?")
	}
	return d.Logs.Append(ctx, b.DeploymentID, b.ID, clean)
}

// BuildFinished records the outcome of a build and, for a final outcome,
// of its deployment, in one transaction. Duplicate reports are ignored.
func (d *Dispatcher) BuildFinished(ctx context.Context, nodeID uuid.UUID, m *agentv1.BuildFinished) error {
	b, err := d.buildFor(ctx, nodeID, m.GetBuildId())
	if errors.Is(err, errNotYours) {
		return nil
	}
	if err != nil {
		return err
	}
	if b.FinishedAt != nil {
		return nil
	}
	dep, err := d.Store.GetDeploymentByID(ctx, b.DeploymentID)
	if err != nil {
		return fmt.Errorf("read deployment: %w", err)
	}
	result, message, digest := d.interpret(ctx, &b, m)
	logBytes := max(m.GetLogBytes(), 0)

	var finished store.Build
	err = d.Store.InTx(ctx, func(q *store.Queries) error {
		finished, err = q.FinishBuild(ctx, store.FinishBuildParams{
			ID: b.ID, Result: &result, Message: message, ImageDigest: digest, LogBytes: &logBytes,
		})
		if err != nil {
			return err
		}
		switch result {
		case store.BuildResultSucceeded:
			_, err = q.MarkBuilt(ctx, store.MarkBuiltParams{ID: dep.ID, ImageDigest: digest})
		case store.BuildResultFailed, store.BuildResultTimedOut:
			_, err = q.MarkFailed(ctx, store.MarkFailedParams{ID: dep.ID, Reason: message})
		case store.BuildResultCancelled:
			_, err = q.MarkCancelled(ctx, store.MarkCancelledParams{ID: dep.ID, Reason: "canceled by a user"})
		default:
			// Infrastructure failures leave the deployment building: its
			// owner retries on another node.
		}
		if store.IsNotFound(err) {
			return nil // the deployment already ended (e.g. canceled meanwhile)
		}
		return err
	})
	if store.IsNotFound(err) {
		return nil // another report won
	}
	if err != nil {
		return fmt.Errorf("record build result: %w", err)
	}
	d.metrics.finished.WithLabelValues(string(result)).Inc()
	d.metrics.duration.Observe(time.Since(b.DispatchedAt).Seconds())
	d.persistLog(ctx, &dep, &finished)
	if result != store.BuildResultInfraError {
		d.ended(ctx, dep.ID)
	}
	_ = d.Redis.Publish(ctx, wakeChannel, dep.ID.String()).Err()
	return nil
}

// interpret maps an agent's report to a build result, verifying a
// reported image really is in the registry before trusting it.
func (d *Dispatcher) interpret(ctx context.Context, b *store.Build, m *agentv1.BuildFinished) (store.BuildResult, string, *string) {
	msg := sanitize(m.GetMessage())
	switch m.GetResult() {
	case agentv1.BuildResult_BUILD_RESULT_SUCCEEDED:
		digest := m.GetImageDigest()
		if !registry.ValidDigest(digest) {
			return store.BuildResultInfraError, "the node reported an invalid image digest", nil
		}
		app, err := d.Store.GetAppByID(ctx, b.AppID)
		if err != nil {
			return store.BuildResultInfraError, "could not verify the image", nil
		}
		ok, err := d.Registry.ManifestExists(ctx, apps.RepositoryName(app.WorkspaceID, app.ID), digest)
		if err != nil || !ok {
			return store.BuildResultInfraError, "the pushed image is not in the registry", nil
		}
		return store.BuildResultSucceeded, "built and pushed", &digest
	case agentv1.BuildResult_BUILD_RESULT_FAILED:
		return store.BuildResultFailed, orDefault(msg, "the build failed; see the build log"), nil
	case agentv1.BuildResult_BUILD_RESULT_TIMED_OUT:
		return store.BuildResultTimedOut, orDefault(msg, "the build exceeded its time limit"), nil
	case agentv1.BuildResult_BUILD_RESULT_CANCELED:
		return store.BuildResultCancelled, "canceled", nil
	default:
		return store.BuildResultInfraError, orDefault(msg, "the node failed to run the build"), nil
	}
}

// AgentConnected reconciles a node's builds when its agent (re)connects:
// a build the node had accepted but no longer reports was lost (the agent
// restarted), and is retried elsewhere.
func (d *Dispatcher) AgentConnected(ctx context.Context, nodeID uuid.UUID, activeIDs []string) error {
	running, err := d.Store.ListActiveBuildsOnNode(ctx, &nodeID)
	if err != nil {
		return fmt.Errorf("list node builds: %w", err)
	}
	for i := range running {
		b := &running[i]
		if b.StartedAt == nil || slices.Contains(activeIDs, b.ID.String()) {
			continue
		}
		dep, err := d.Store.GetDeploymentByID(ctx, b.DeploymentID)
		if err != nil {
			continue
		}
		d.finishLost(ctx, &dep, b, "the agent on node "+b.NodeName+" restarted")
		_ = d.Redis.Publish(ctx, wakeChannel, dep.ID.String()).Err()
	}
	return nil
}

func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, strings.ToValidUTF8(s, "?"))
	if len(s) > maxMessageLength {
		s = s[:maxMessageLength]
	}
	return strings.TrimSpace(s)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
