package workspace

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
)

// View is a workspace as seen by one member.
type View struct {
	Workspace store.Workspace
	// Role is the caller's role in the workspace.
	Role store.WorkspaceRole
}

// Personal reports whether this is a user's personal workspace.
func (v *View) Personal() bool {
	return v.Workspace.PersonalOwnerID != nil
}

// Allows reports whether the caller's role includes the permissions of minRole.
func (v *View) Allows(minRole store.WorkspaceRole) bool {
	return atLeast(v.Role, minRole)
}

// Resolve looks a workspace up through the actor's membership inside a
// transaction (or with any Queries). Non-members get not found.
func Resolve(ctx context.Context, q *store.Queries, actor Actor, slug string) (View, error) {
	return lookup(ctx, q, actor, slug)
}

// Service implements workspace operations.
type Service struct {
	store         *store.Store
	invitationTTL time.Duration
}

// NewService returns a workspace service.
func NewService(s *store.Store, invitationTTL time.Duration) *Service {
	return &Service{store: s, invitationTTL: invitationTTL}
}

// errNotFound is the single answer for "missing" and "not yours".
func errNotFound() error {
	return apperr.NotFound("workspace not found")
}

// lookup resolves slug through the actor's membership.
func lookup(ctx context.Context, q *store.Queries, actor Actor, slug string) (View, error) {
	if !ValidSlug(slug) {
		return View{}, errNotFound()
	}
	row, err := q.GetWorkspaceForMember(ctx, store.GetWorkspaceForMemberParams{Slug: slug, UserID: actor.UserID})
	if store.IsNotFound(err) {
		return View{}, errNotFound()
	}
	if err != nil {
		return View{}, fmt.Errorf("look up workspace: %w", err)
	}
	return View{Workspace: row.Workspace, Role: row.Role}, nil
}

// Get returns a workspace the actor belongs to.
func (s *Service) Get(ctx context.Context, actor Actor, slug string) (View, error) {
	return lookup(ctx, s.store.Queries, actor, slug)
}

// List returns the actor's workspaces ordered by slug, after the given
// slug (empty for the first page).
func (s *Service) List(ctx context.Context, actor Actor, afterSlug string, limit int32) ([]View, error) {
	rows, err := s.store.ListWorkspacesForMember(ctx, store.ListWorkspacesForMemberParams{
		UserID: actor.UserID, AfterSlug: afterSlug, RowLimit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("list workspaces: %w", err)
	}
	out := make([]View, len(rows))
	for i, r := range rows {
		out[i] = View{Workspace: r.Workspace, Role: r.Role}
	}
	return out, nil
}

// Create makes a workspace with the actor as its owner.
func (s *Service) Create(ctx context.Context, actor Actor, name, slug string) (View, error) {
	name, err := normalizeName(name)
	if err != nil {
		return View{}, err
	}
	if !ValidSlug(slug) {
		return View{}, apperr.Invalid("invalid_slug",
			"slug must be 1 to 40 lower-case letters, digits or inner hyphens, without \"--\"")
	}
	var view View
	txErr := s.store.InTx(ctx, func(q *store.Queries) error {
		taken, err := q.WorkspaceSlugExists(ctx, slug)
		if err != nil {
			return fmt.Errorf("check slug: %w", err)
		}
		if taken {
			return apperr.Conflict("slug_taken", "the slug %q is already in use", slug)
		}
		ws, err := createOwned(ctx, q, actor, name, slug, nil)
		if err != nil {
			return err
		}
		view = View{Workspace: ws, Role: store.WorkspaceRoleOwner}
		return nil
	})
	if store.IsUniqueViolation(txErr, "workspaces_slug_key") {
		// Lost a race with a concurrent create of the same slug.
		return View{}, apperr.Conflict("slug_taken", "the slug %q is already in use", slug)
	}
	return view, txErr
}

// createOwned inserts a workspace, its owner membership and the audit entry.
func createOwned(ctx context.Context, q *store.Queries, actor Actor, name, slug string, personalOwner *uuid.UUID) (store.Workspace, error) {
	ws, err := q.CreateWorkspace(ctx, store.CreateWorkspaceParams{Name: name, Slug: slug, PersonalOwnerID: personalOwner})
	if err != nil {
		return store.Workspace{}, fmt.Errorf("create workspace: %w", err)
	}
	_, err = q.CreateMembership(ctx, store.CreateMembershipParams{
		WorkspaceID: ws.ID, UserID: actor.UserID, Role: store.WorkspaceRoleOwner,
	})
	if err != nil {
		return store.Workspace{}, fmt.Errorf("create owner membership: %w", err)
	}
	return ws, audit.Record(ctx, q, &audit.Entry{
		WorkspaceID: audit.Ptr(ws.ID), ActorID: audit.Ptr(actor.UserID), IP: actor.IP,
		Action: audit.ActionWorkspaceCreate, TargetType: audit.TargetWorkspace, TargetID: ws.ID.String(),
		Metadata: map[string]any{"slug": ws.Slug, "name": ws.Name, "personal": personalOwner != nil},
	})
}

// CreatePersonal creates the personal workspace given to every user at
// first sign-in, inside the sign-in transaction q.
func CreatePersonal(ctx context.Context, q *store.Queries, user *store.User, ip *netip.Addr) (store.Workspace, error) {
	slug, err := personalSlug(ctx, q, user.Email)
	if err != nil {
		return store.Workspace{}, err
	}
	display := user.Name
	if display == "" {
		display, _, _ = strings.Cut(user.Email, "@")
	}
	name := display + "'s workspace"
	if utf8.RuneCountInString(name) > maxNameLength {
		name = "Personal workspace"
	}
	return createOwned(ctx, q, Actor{UserID: user.ID, IP: ip}, name, slug, audit.Ptr(user.ID))
}

// Rename changes a workspace's display name (admins and owners).
func (s *Service) Rename(ctx context.Context, actor Actor, slug, name string) (View, error) {
	name, err := normalizeName(name)
	if err != nil {
		return View{}, err
	}
	var view View
	txErr := s.store.InTx(ctx, func(q *store.Queries) error {
		v, err := lookup(ctx, q, actor, slug)
		if err != nil {
			return err
		}
		if !atLeast(v.Role, store.WorkspaceRoleAdmin) {
			return apperr.Forbidden("only admins and owners can rename a workspace")
		}
		ws, err := q.RenameWorkspace(ctx, store.RenameWorkspaceParams{ID: v.Workspace.ID, Name: name})
		if err != nil {
			return fmt.Errorf("rename workspace: %w", err)
		}
		view = View{Workspace: ws, Role: v.Role}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: audit.Ptr(ws.ID), ActorID: audit.Ptr(actor.UserID), IP: actor.IP,
			Action: audit.ActionWorkspaceUpdate, TargetType: audit.TargetWorkspace, TargetID: ws.ID.String(),
			Metadata: map[string]any{"old_name": v.Workspace.Name, "new_name": ws.Name},
		})
	})
	return view, txErr
}

// Delete removes a workspace (owners only). A personal workspace cannot be
// deleted while it is its owner's only workspace, so every user always has
// somewhere to work.
func (s *Service) Delete(ctx context.Context, actor Actor, slug string) error {
	return s.store.InTx(ctx, func(q *store.Queries) error {
		v, err := lookup(ctx, q, actor, slug)
		if err != nil {
			return err
		}
		if v.Role != store.WorkspaceRoleOwner {
			return apperr.Forbidden("only owners can delete a workspace")
		}
		if owner := v.Workspace.PersonalOwnerID; owner != nil {
			n, countErr := q.CountUserMemberships(ctx, *owner)
			if countErr != nil {
				return fmt.Errorf("count memberships: %w", countErr)
			}
			if n <= 1 {
				return apperr.Conflict("last_workspace",
					"a personal workspace cannot be deleted while it is its owner's only workspace")
			}
		}
		apps, err := q.CountApps(ctx, v.Workspace.ID)
		if err != nil {
			return fmt.Errorf("count apps: %w", err)
		}
		if apps > 0 {
			return apperr.Conflict("workspace_has_apps",
				"delete the workspace's apps first (deleted apps are cleaned up within a few minutes)")
		}
		if err := q.DeleteWorkspace(ctx, v.Workspace.ID); err != nil {
			return fmt.Errorf("delete workspace: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: audit.Ptr(v.Workspace.ID), ActorID: audit.Ptr(actor.UserID), IP: actor.IP,
			Action: audit.ActionWorkspaceDelete, TargetType: audit.TargetWorkspace, TargetID: v.Workspace.ID.String(),
			Metadata: map[string]any{"slug": v.Workspace.Slug, "name": v.Workspace.Name},
		})
	})
}
