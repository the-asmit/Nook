package apps

import (
	"context"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/routes"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// RouteEvents announces that an app's route changed (routes.Publisher).
type RouteEvents interface {
	Changed(ctx context.Context, appID uuid.UUID)
}

// Limits on access grants.
const (
	maxGrants           = 1000
	maxGrantsPerRequest = 50
)

// Access is an app's access policy as shown to members.
type Access struct {
	// Mode is the configured mode; Effective is what applies (public
	// falls back to workspace where the instance forbids public apps).
	Mode          store.AppAccessMode
	Effective     string
	PublicAllowed bool
	Grants        []store.AppAccessGrant
}

// NormalizeEmail validates an email address for a grant and returns it in
// lower case. Errors never echo more than the address itself.
func NormalizeEmail(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s || len(s) > 254 || !strings.Contains(s[strings.LastIndex(s, "@")+1:], ".") {
		return "", apperr.Invalid("invalid_email", "%q is not an email address", truncateKey(raw))
	}
	return s, nil
}

// GetAccess returns an app's access policy (any member).
func (s *Service) GetAccess(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) (Access, error) {
	_, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	if err != nil {
		return Access{}, err
	}
	return s.access(ctx, s.store.Queries, &app)
}

func (s *Service) access(ctx context.Context, q *store.Queries, app *store.App) (Access, error) {
	grants, err := q.ListAccessGrants(ctx, app.ID)
	if err != nil {
		return Access{}, fmt.Errorf("list grants: %w", err)
	}
	return Access{
		Mode: app.AccessMode, Effective: routes.Effective(string(app.AccessMode), s.cfg.AllowPublicApps),
		PublicAllowed: s.cfg.AllowPublicApps, Grants: grants,
	}, nil
}

// SetAccessMode changes who may open an app (admins and owners). Public
// needs the instance to allow public apps.
func (s *Service) SetAccessMode(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, mode store.AppAccessMode) (Access, error) {
	if !mode.Valid() {
		return Access{}, apperr.Invalid("invalid_mode", "mode must be workspace, restricted or public")
	}
	if mode == store.AppAccessModePublic && !s.cfg.AllowPublicApps {
		return Access{}, apperr.Forbidden("this Nook installation does not allow public apps")
	}
	return s.changeAccess(ctx, actor, wsSlug, appSlug, func(q *store.Queries, v workspace.View, app *store.App) error {
		updated, err := q.SetAccessMode(ctx, store.SetAccessModeParams{ID: app.ID, AccessMode: mode})
		if err != nil {
			return fmt.Errorf("set access mode: %w", err)
		}
		*app = updated
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionAccessSetMode, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{"app": app.Slug, "mode": string(mode)},
		})
	})
}

// Grant gives people access by email (admins and owners).
func (s *Service) Grant(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, emails []string) (Access, error) {
	if len(emails) == 0 || len(emails) > maxGrantsPerRequest {
		return Access{}, apperr.Invalid("invalid_emails", "grant between 1 and %d emails at once", maxGrantsPerRequest)
	}
	clean := make([]string, 0, len(emails))
	for _, e := range emails {
		n, err := NormalizeEmail(e)
		if err != nil {
			return Access{}, err
		}
		if !slices.Contains(clean, n) {
			clean = append(clean, n)
		}
	}
	return s.changeAccess(ctx, actor, wsSlug, appSlug, func(q *store.Queries, v workspace.View, app *store.App) error {
		count, err := q.CountAccessGrants(ctx, app.ID)
		if err != nil {
			return fmt.Errorf("count grants: %w", err)
		}
		if int(count)+len(clean) > maxGrants {
			return apperr.Invalid("too_many_grants", "an app may have at most %d grants", maxGrants)
		}
		for _, e := range clean {
			if _, err := q.AddAccessGrant(ctx, store.AddAccessGrantParams{AppID: app.ID, Email: e, GrantedBy: &actor.UserID}); err != nil {
				return fmt.Errorf("add grant: %w", err)
			}
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionAccessGrant, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{"app": app.Slug, "emails": clean},
		})
	})
}

// Revoke removes a grant (admins and owners).
func (s *Service) Revoke(ctx context.Context, actor workspace.Actor, wsSlug, appSlug, email string) (Access, error) {
	n, err := NormalizeEmail(email)
	if err != nil {
		return Access{}, err
	}
	return s.changeAccess(ctx, actor, wsSlug, appSlug, func(q *store.Queries, v workspace.View, app *store.App) error {
		removed, err := q.DeleteAccessGrant(ctx, store.DeleteAccessGrantParams{AppID: app.ID, Email: n})
		if err != nil {
			return fmt.Errorf("delete grant: %w", err)
		}
		if removed == 0 {
			return apperr.NotFound("%s has no grant on this app", n)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionAccessRevoke, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{"app": app.Slug, "email": n},
		})
	})
}

func (s *Service) changeAccess(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string,
	change func(*store.Queries, workspace.View, *store.App) error) (Access, error) {
	var out Access
	var appID uuid.UUID
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug)
		if err != nil {
			return err
		}
		if !v.Allows(store.WorkspaceRoleAdmin) {
			return apperr.Forbidden("only workspace admins and owners can manage access")
		}
		if changeErr := change(q, v, &app); changeErr != nil {
			return changeErr
		}
		appID = app.ID
		out, err = s.access(ctx, q, &app)
		return err
	})
	if err != nil {
		return Access{}, err
	}
	s.events.Changed(ctx, appID)
	return out, nil
}

// Decide reports whether the person with this (verified) email may open
// the app: anyone for public apps; people granted by email; workspace
// members in workspace mode; workspace admins and owners in restricted
// mode. Members are matched by their account's email.
func Decide(ctx context.Context, q *store.Queries, app *store.App, email string, allowPublic bool) (bool, error) {
	mode := routes.Effective(string(app.AccessMode), allowPublic)
	if mode == routes.AccessPublic {
		return true, nil
	}
	granted, err := q.AccessGranted(ctx, store.AccessGrantedParams{AppID: app.ID, Email: email})
	if err != nil {
		return false, fmt.Errorf("check grant: %w", err)
	}
	if granted {
		return true, nil
	}
	role, err := q.MemberRoleByEmail(ctx, store.MemberRoleByEmailParams{WorkspaceID: app.WorkspaceID, Email: email})
	if store.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check membership: %w", err)
	}
	if mode == routes.AccessRestricted {
		return role == store.WorkspaceRoleAdmin || role == store.WorkspaceRoleOwner, nil
	}
	return true, nil
}
