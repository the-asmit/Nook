package workspace

import (
	"context"
	"fmt"
	"net/netip"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
)

// Invite creates an invitation for email to join with role. Admins invite
// members and admins; only owners can invite owners. Nook does not send
// email: the invitee is admitted the next time they sign in with that
// address, so the inviter shares the Nook URL themselves.
func (s *Service) Invite(ctx context.Context, actor Actor, slug, email string, role store.WorkspaceRole) (store.Invitation, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return store.Invitation{}, err
	}
	if !role.Valid() {
		return store.Invitation{}, apperr.Invalid("invalid_role", "role must be owner, admin or member")
	}
	var inv store.Invitation
	txErr := s.store.InTx(ctx, func(q *store.Queries) error {
		v, err := lookup(ctx, q, actor, slug)
		if err != nil {
			return err
		}
		if !atLeast(v.Role, store.WorkspaceRoleAdmin) {
			return apperr.Forbidden("only admins and owners can invite people")
		}
		if role == store.WorkspaceRoleOwner && v.Role != store.WorkspaceRoleOwner {
			return apperr.Forbidden("only owners can invite owners")
		}
		member, err := q.IsWorkspaceMemberByEmail(ctx, store.IsWorkspaceMemberByEmailParams{WorkspaceID: v.Workspace.ID, Email: email})
		if err != nil {
			return fmt.Errorf("check membership: %w", err)
		}
		if member {
			return apperr.Conflict("already_member", "%s is already a member", email)
		}
		err = q.DeleteExpiredOpenInvitation(ctx, store.DeleteExpiredOpenInvitationParams{
			WorkspaceID: v.Workspace.ID, Email: email,
		})
		if err != nil {
			return fmt.Errorf("clear expired invitation: %w", err)
		}
		inv, err = q.CreateInvitation(ctx, store.CreateInvitationParams{
			WorkspaceID: v.Workspace.ID, Email: email, Role: role,
			InvitedBy: audit.Ptr(actor.UserID), TtlSeconds: s.invitationTTL.Seconds(),
		})
		if err != nil {
			return fmt.Errorf("create invitation: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: audit.Ptr(v.Workspace.ID), ActorID: audit.Ptr(actor.UserID), IP: actor.IP,
			Action: audit.ActionInvitationCreate, TargetType: audit.TargetInvitation, TargetID: inv.ID.String(),
			Metadata: map[string]any{"email": email, "role": role},
		})
	})
	if store.IsUniqueViolation(txErr, "invitations_open_key") {
		return store.Invitation{}, apperr.Conflict("invitation_exists", "%s already has an open invitation", email)
	}
	return inv, txErr
}

// ListInvitations lists open, unexpired invitations (admins and owners).
func (s *Service) ListInvitations(ctx context.Context, actor Actor, slug string, after uuid.UUID, limit int32) ([]store.Invitation, error) {
	v, err := lookup(ctx, s.store.Queries, actor, slug)
	if err != nil {
		return nil, err
	}
	if !atLeast(v.Role, store.WorkspaceRoleAdmin) {
		return nil, apperr.Forbidden("only admins and owners can see invitations")
	}
	inv, err := s.store.ListOpenInvitations(ctx, store.ListOpenInvitationsParams{
		WorkspaceID: v.Workspace.ID, AfterID: after, RowLimit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	return inv, nil
}

// RevokeInvitation deletes an open invitation (admins and owners).
// Revoking one that no longer exists succeeds (idempotent).
func (s *Service) RevokeInvitation(ctx context.Context, actor Actor, slug string, id uuid.UUID) error {
	return s.store.InTx(ctx, func(q *store.Queries) error {
		v, err := lookup(ctx, q, actor, slug)
		if err != nil {
			return err
		}
		if !atLeast(v.Role, store.WorkspaceRoleAdmin) {
			return apperr.Forbidden("only admins and owners can revoke invitations")
		}
		inv, err := q.DeleteOpenInvitation(ctx, store.DeleteOpenInvitationParams{ID: id, WorkspaceID: v.Workspace.ID})
		if store.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("delete invitation: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: audit.Ptr(v.Workspace.ID), ActorID: audit.Ptr(actor.UserID), IP: actor.IP,
			Action: audit.ActionInvitationRevoke, TargetType: audit.TargetInvitation, TargetID: inv.ID.String(),
			Metadata: map[string]any{"email": inv.Email, "role": inv.Role},
		})
	})
}

// AcceptInvitations turns every open invitation for user's email into a
// membership, inside the sign-in transaction q. An existing membership
// keeps its role.
func AcceptInvitations(ctx context.Context, q *store.Queries, user *store.User, ip *netip.Addr) error {
	accepted, err := q.AcceptOpenInvitations(ctx, user.Email)
	if err != nil {
		return fmt.Errorf("accept invitations: %w", err)
	}
	for i := range accepted {
		inv := &accepted[i]
		if _, err := q.CreateMembership(ctx, store.CreateMembershipParams{
			WorkspaceID: inv.WorkspaceID, UserID: user.ID, Role: inv.Role,
		}); err != nil {
			return fmt.Errorf("join workspace: %w", err)
		}
		if err := audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: audit.Ptr(inv.WorkspaceID), ActorID: audit.Ptr(user.ID), IP: ip,
			Action: audit.ActionInvitationAccept, TargetType: audit.TargetInvitation, TargetID: inv.ID.String(),
			Metadata: map[string]any{"role": inv.Role},
		}); err != nil {
			return err
		}
	}
	return nil
}
