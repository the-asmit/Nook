package nodes

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/store"
)

// List returns live nodes ordered by name, after afterName.
func (r *Registry) List(ctx context.Context, afterName string, limit int32) ([]store.Node, error) {
	nodes, err := r.store.ListNodes(ctx, store.ListNodesParams{AfterName: afterName, RowLimit: limit})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	return nodes, nil
}

// Resolve finds a live node by ID or name.
func (r *Registry) Resolve(ctx context.Context, ref string) (store.Node, error) {
	var n store.Node
	var err error
	if id, parseErr := uuid.Parse(ref); parseErr == nil {
		n, err = r.store.GetLiveNodeByID(ctx, id)
	} else if ValidNodeName(ref) {
		n, err = r.store.GetLiveNodeByName(ctx, ref)
	} else {
		return store.Node{}, apperr.NotFound("node not found")
	}
	if store.IsNotFound(err) {
		return store.Node{}, apperr.NotFound("node not found")
	}
	if err != nil {
		return store.Node{}, fmt.Errorf("look up node: %w", err)
	}
	return n, nil
}

// LatestHeartbeat returns a node's most recent heartbeat, if any.
func (r *Registry) LatestHeartbeat(ctx context.Context, nodeID uuid.UUID) (*Sample, error) {
	return r.heartbeats.Latest(ctx, nodeID)
}

// Events returns a node's most recent state transitions, newest first.
func (r *Registry) Events(ctx context.Context, nodeID uuid.UUID, limit int32) ([]store.NodeEvent, error) {
	evs, err := r.store.ListNodeEvents(ctx, store.ListNodeEventsParams{NodeID: nodeID, RowLimit: limit})
	if err != nil {
		return nil, fmt.Errorf("list node events: %w", err)
	}
	return evs, nil
}

// SetDraining marks a node as draining (the scheduler of a later stage
// moves work off it and places nothing new on it) or undoes that. Health
// still applies: a draining node that stops heartbeating becomes suspect
// and dead, and returns to draining when it recovers.
func (r *Registry) SetDraining(ctx context.Context, actor audit.Actor, ref string, draining bool) (store.Node, error) {
	node, resolveErr := r.Resolve(ctx, ref)
	if resolveErr != nil {
		return store.Node{}, resolveErr
	}
	var ev *Event
	var out store.Node
	err := r.store.InTx(ctx, func(q *store.Queries) error {
		n, err := q.LockLiveNode(ctx, node.ID)
		if store.IsNotFound(err) {
			return apperr.NotFound("node not found")
		}
		if err != nil {
			return fmt.Errorf("lock node: %w", err)
		}
		status := n.Status
		if status == store.NodeStatusReady || status == store.NodeStatusDraining {
			status = healthyStatus(draining)
		}
		if err = q.SetNodeDraining(ctx, store.SetNodeDrainingParams{ID: n.ID, Draining: draining, Status: status}); err != nil {
			return fmt.Errorf("set draining: %w", err)
		}
		if status != n.Status {
			reason := "drained by an administrator"
			if !draining {
				reason = "undrained by an administrator"
			}
			from := n.Status
			if ev, err = recordTransition(ctx, q, n.ID, n.Name, &from, status, reason); err != nil {
				return err
			}
		}
		n.Draining, n.Status, out = draining, status, n
		action := audit.ActionNodeDrain
		if !draining {
			action = audit.ActionNodeUndrain
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &actor.UserID, IP: actor.IP, Action: action, TargetType: audit.TargetNode, TargetID: n.ID.String(),
			Metadata: map[string]any{"name": n.Name},
		})
	})
	if err != nil {
		return store.Node{}, err
	}
	r.publish(ctx, ev)
	return out, nil
}

// Remove takes a node out of the installation: all its certificates are
// revoked at once and its agent, wherever it is connected, is cut off.
// Removing a node that is already gone reports not found.
func (r *Registry) Remove(ctx context.Context, actor audit.Actor, ref string) (store.Node, error) {
	node, resolveErr := r.Resolve(ctx, ref)
	if resolveErr != nil {
		return store.Node{}, resolveErr
	}
	var ev *Event
	err := r.store.InTx(ctx, func(q *store.Queries) error {
		n, err := q.LockLiveNode(ctx, node.ID)
		if store.IsNotFound(err) {
			return apperr.NotFound("node not found")
		}
		if err != nil {
			return fmt.Errorf("lock node: %w", err)
		}
		revoked, err := q.RevokeNodeCertificates(ctx, n.ID)
		if err != nil {
			return fmt.Errorf("revoke certificates: %w", err)
		}
		if err = q.RemoveNode(ctx, n.ID); err != nil {
			return fmt.Errorf("remove node: %w", err)
		}
		from := n.Status
		if ev, err = recordTransition(ctx, q, n.ID, n.Name, &from, store.NodeStatusRemoved, "removed by an administrator"); err != nil {
			return err
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionNodeRemove, TargetType: audit.TargetNode, TargetID: n.ID.String(),
			Metadata: map[string]any{"name": n.Name, "revoked_certificates": revoked},
		})
	})
	if err != nil {
		return store.Node{}, err
	}
	r.publish(ctx, ev)
	if err := r.publisher.Control(ctx, ControlMessage{Action: ControlDisconnect, NodeID: node.ID}); err != nil {
		// The certificate is revoked regardless; the stream ends at the
		// latest when the agent reconnects.
		r.logger.WarnContext(ctx, "publish disconnect", "error", err.Error())
	}
	if err := r.heartbeats.Forget(ctx, node.ID); err != nil {
		r.logger.WarnContext(ctx, "forget heartbeats", "error", err.Error())
	}
	return node, nil
}

// CreateJoinToken issues a join token valid for ttl and maxUses joins.
func (r *Registry) CreateJoinToken(ctx context.Context, actor audit.Actor, maxUses int32, ttl time.Duration) (string, store.JoinToken, error) {
	if ttl == 0 {
		ttl = r.cfg.JoinTokenTTL
	}
	if ttl < time.Minute || ttl > MaxJoinTokenTTL {
		return "", store.JoinToken{}, apperr.Invalid("invalid_expiry", "expiry must be between 1 minute and %s", MaxJoinTokenTTL)
	}
	if maxUses == 0 {
		maxUses = 1
	}
	if maxUses < 1 || maxUses > 1000 {
		return "", store.JoinToken{}, apperr.Invalid("invalid_max_uses", "max_uses must be between 1 and 1000")
	}
	raw, prefix := NewJoinToken()
	var tok store.JoinToken
	err := r.store.InTx(ctx, func(q *store.Queries) error {
		var err error
		tok, err = q.CreateJoinToken(ctx, store.CreateJoinTokenParams{
			TokenHash: auth.Hash(raw), Prefix: prefix, CreatedBy: &actor.UserID,
			TtlSeconds: ttl.Seconds(), MaxUses: maxUses,
		})
		if err != nil {
			return fmt.Errorf("create join token: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionJoinTokenCreate, TargetType: audit.TargetJoinToken,
			TargetID: tok.ID.String(), Metadata: map[string]any{"max_uses": maxUses, "expires_at": tok.ExpiresAt},
		})
	})
	return raw, tok, err
}

// ListJoinTokens returns recent join tokens, newest first, before beforeID.
func (r *Registry) ListJoinTokens(ctx context.Context, beforeID uuid.UUID, limit int32) ([]store.JoinToken, error) {
	toks, err := r.store.ListJoinTokens(ctx, store.ListJoinTokensParams{BeforeID: beforeID, RowLimit: limit})
	if err != nil {
		return nil, fmt.Errorf("list join tokens: %w", err)
	}
	return toks, nil
}

// RevokeJoinToken revokes a join token; revoking one that is already
// revoked or unknown succeeds (idempotent).
func (r *Registry) RevokeJoinToken(ctx context.Context, actor audit.Actor, id uuid.UUID) error {
	return r.store.InTx(ctx, func(q *store.Queries) error {
		tok, err := q.RevokeJoinToken(ctx, id)
		if store.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("revoke join token: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionJoinTokenRevoke, TargetType: audit.TargetJoinToken,
			TargetID: tok.ID.String(), Metadata: map[string]any{"prefix": tok.Prefix},
		})
	})
}

// SetLabels replaces a node's labels (instance admins). Labels steer
// placement, such as which node hosts the app database server.
func (r *Registry) SetLabels(ctx context.Context, actor audit.Actor, ref string, labels map[string]string) (store.Node, error) {
	node, err := r.Resolve(ctx, ref)
	if err != nil {
		return store.Node{}, err
	}
	data, err := encodeLabels(labels)
	if err != nil {
		return store.Node{}, err
	}
	var out store.Node
	err = r.store.InTx(ctx, func(q *store.Queries) error {
		n, lockErr := q.LockLiveNode(ctx, node.ID)
		if store.IsNotFound(lockErr) {
			return apperr.NotFound("node not found")
		}
		if lockErr != nil {
			return fmt.Errorf("lock node: %w", lockErr)
		}
		if setErr := q.SetNodeLabels(ctx, store.SetNodeLabelsParams{ID: n.ID, Labels: data}); setErr != nil {
			return fmt.Errorf("set labels: %w", setErr)
		}
		n.Labels, out = data, n
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &actor.UserID, IP: actor.IP, Action: audit.ActionNodeLabel, TargetType: audit.TargetNode, TargetID: n.ID.String(),
			Metadata: map[string]any{"name": n.Name, "labels": labels},
		})
	})
	return out, err
}
