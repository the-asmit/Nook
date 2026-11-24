package workspace

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
)

// Member is one row of a workspace's member list.
type Member struct {
	UserID    uuid.UUID
	Email     string
	Name      string
	AvatarURL string
	Role      store.WorkspaceRole
	JoinedAt  time.Time
}

// MemberCursor positions a member listing (ordered by email, then ID).
type MemberCursor struct {
	Email  string
	UserID uuid.UUID
}

// ListMembers lists a workspace's members (any member may read).
func (s *Service) ListMembers(ctx context.Context, actor Actor, slug string, after MemberCursor, limit int32) ([]Member, error) {
	v, err := lookup(ctx, s.store.Queries, actor, slug)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListWorkspaceMembers(ctx, store.ListWorkspaceMembersParams{
		WorkspaceID: v.Workspace.ID, AfterEmail: after.Email, AfterID: after.UserID, RowLimit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	out := make([]Member, len(rows))
	for i, r := range rows {
		out[i] = Member{UserID: r.ID, Email: r.Email, Name: r.Name, AvatarURL: r.AvatarUrl, Role: r.Role, JoinedAt: r.CreatedAt}
	}
	return out, nil
}

// lockForMembershipChange resolves the workspace and locks its row for the
// rest of the transaction.
func lockForMembershipChange(ctx context.Context, q *store.Queries, actor Actor, slug string) (View, error) {
	v, err := lookup(ctx, q, actor, slug)
	if err != nil {
		return View{}, err
	}
	_, err = q.LockWorkspace(ctx, v.Workspace.ID)
	if err != nil {
		return View{}, fmt.Errorf("lock workspace: %w", err)
	}
	// Re-read the actor's role now that concurrent changes are excluded.
	role, err := q.GetMemberRole(ctx, store.GetMemberRoleParams{WorkspaceID: v.Workspace.ID, UserID: actor.UserID})
	if store.IsNotFound(err) {
		return View{}, errNotFound()
	}
	if err != nil {
		return View{}, fmt.Errorf("read role: %w", err)
	}
	v.Role = role
	return v, nil
}

// ensureNotLastOwner fails if removing ownership from one owner would leave
// the workspace without any.
func ensureNotLastOwner(ctx context.Context, q *store.Queries, workspaceID uuid.UUID) error {
	n, err := q.CountWorkspaceOwners(ctx, workspaceID)
	if err != nil {
		return fmt.Errorf("count owners: %w", err)
	}
	if n <= 1 {
		return apperr.Conflict("last_owner", "a workspace must always keep at least one owner")
	}
	return nil
}

// ChangeRole sets a member's role. Admins manage members and admins; only
// owners may grant or take away ownership; the last owner cannot be demoted.
func (s *Service) ChangeRole(ctx context.Context, actor Actor, slug string, target uuid.UUID, role store.WorkspaceRole) error {
	if !role.Valid() {
		return apperr.Invalid("invalid_role", "role must be owner, admin or member")
	}
	return s.store.InTx(ctx, func(q *store.Queries) error {
		v, err := lockForMembershipChange(ctx, q, actor, slug)
		if err != nil {
			return err
		}
		if !atLeast(v.Role, store.WorkspaceRoleAdmin) {
			return apperr.Forbidden("only admins and owners can change roles")
		}
		current, err := q.GetMemberRole(ctx, store.GetMemberRoleParams{WorkspaceID: v.Workspace.ID, UserID: target})
		if store.IsNotFound(err) {
			return apperr.NotFound("member not found")
		}
		if err != nil {
			return fmt.Errorf("read member role: %w", err)
		}
		if (current == store.WorkspaceRoleOwner || role == store.WorkspaceRoleOwner) && v.Role != store.WorkspaceRoleOwner {
			return apperr.Forbidden("only owners can grant or remove the owner role")
		}
		if current == role {
			return nil
		}
		if current == store.WorkspaceRoleOwner {
			if err := ensureNotLastOwner(ctx, q, v.Workspace.ID); err != nil {
				return err
			}
		}
		if _, err := q.UpdateMemberRole(ctx, store.UpdateMemberRoleParams{
			WorkspaceID: v.Workspace.ID, UserID: target, Role: role,
		}); err != nil {
			return fmt.Errorf("update role: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: audit.Ptr(v.Workspace.ID), ActorID: audit.Ptr(actor.UserID), IP: actor.IP,
			Action: audit.ActionMemberRoleChange, TargetType: audit.TargetMembership, TargetID: target.String(),
			Metadata: map[string]any{"old_role": current, "new_role": role},
		})
	})
}

// RemoveMember removes target from the workspace. Anyone may leave; admins
// remove members and admins; only owners remove owners; the last owner
// cannot leave. Removing someone who is not a member succeeds (idempotent).
func (s *Service) RemoveMember(ctx context.Context, actor Actor, slug string, target uuid.UUID) error {
	return s.store.InTx(ctx, func(q *store.Queries) error {
		v, err := lockForMembershipChange(ctx, q, actor, slug)
		if err != nil {
			return err
		}
		self := target == actor.UserID
		if !self && !atLeast(v.Role, store.WorkspaceRoleAdmin) {
			return apperr.Forbidden("only admins and owners can remove other members")
		}
		current, err := q.GetMemberRole(ctx, store.GetMemberRoleParams{WorkspaceID: v.Workspace.ID, UserID: target})
		if store.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read member role: %w", err)
		}
		if current == store.WorkspaceRoleOwner {
			if !self && v.Role != store.WorkspaceRoleOwner {
				return apperr.Forbidden("only owners can remove an owner")
			}
			if err := ensureNotLastOwner(ctx, q, v.Workspace.ID); err != nil {
				return err
			}
		}
		if _, err := q.DeleteMembership(ctx, store.DeleteMembershipParams{WorkspaceID: v.Workspace.ID, UserID: target}); err != nil {
			return fmt.Errorf("delete membership: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: audit.Ptr(v.Workspace.ID), ActorID: audit.Ptr(actor.UserID), IP: actor.IP,
			Action: audit.ActionMemberRemove, TargetType: audit.TargetMembership, TargetID: target.String(),
			Metadata: map[string]any{"role": current, "self": self},
		})
	})
}
