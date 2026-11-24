package identity

import (
	"context"
	"fmt"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
)

// Admin implements the instance administrators' user management.
type Admin struct {
	store *store.Store
}

// NewAdmin returns the user administration service.
func NewAdmin(s *store.Store) *Admin {
	return &Admin{store: s}
}

// ListUsers lists users ordered by email, optionally only one email.
func (a *Admin) ListUsers(ctx context.Context, afterEmail, email string, limit int32) ([]store.User, error) {
	users, err := a.store.ListUsers(ctx, store.ListUsersParams{AfterEmail: afterEmail, EmailFilter: email, RowLimit: limit})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// SetDisabled disables or re-enables a user. Disabling revokes every
// session and API token of the user in the same transaction, so access
// ends immediately; re-enabling does not resurrect them. An admin cannot
// disable themselves, and the last enabled instance admin cannot be
// disabled.
func (a *Admin) SetDisabled(ctx context.Context, actor audit.Actor, target uuid.UUID, disabled bool) (store.User, error) {
	var out store.User
	err := a.store.InTx(ctx, func(q *store.Queries) error {
		if err := q.LockUserAdministration(ctx); err != nil {
			return fmt.Errorf("lock user administration: %w", err)
		}
		u, err := q.LockUser(ctx, target)
		if store.IsNotFound(err) {
			return apperr.NotFound("user not found")
		}
		if err != nil {
			return fmt.Errorf("lock user: %w", err)
		}
		if disabled {
			if u.ID == actor.UserID {
				return apperr.Conflict("cannot_disable_self", "you cannot disable your own account")
			}
			if u.IsInstanceAdmin && u.DisabledAt == nil {
				admins, countErr := q.CountEnabledInstanceAdmins(ctx)
				if countErr != nil {
					return fmt.Errorf("count admins: %w", countErr)
				}
				if admins <= 1 {
					return apperr.Conflict("last_instance_admin", "the last instance administrator cannot be disabled")
				}
			}
		}
		if out, err = q.SetUserDisabled(ctx, store.SetUserDisabledParams{ID: target, Disabled: disabled}); err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		meta := map[string]any{"email": u.Email}
		action := audit.ActionUserEnable
		if disabled {
			action = audit.ActionUserDisable
			sessions, err := q.RevokeUserSessions(ctx, target)
			if err != nil {
				return fmt.Errorf("revoke sessions: %w", err)
			}
			tokens, err := q.RevokeUserAPITokens(ctx, target)
			if err != nil {
				return fmt.Errorf("revoke tokens: %w", err)
			}
			meta["revoked_sessions"], meta["revoked_tokens"] = sessions, tokens
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &actor.UserID, IP: actor.IP, Action: action, TargetType: audit.TargetUser, TargetID: target.String(), Metadata: meta,
		})
	})
	return out, err
}
