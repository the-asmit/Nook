// Package workspace implements workspaces (Nook's tenants), their
// memberships and invitations, and the role-based access rules for them.
//
// Every operation first resolves the workspace through the caller's own
// membership. A caller who is not a member gets "not found", exactly as if
// the workspace did not exist, so slugs and IDs of other tenants cannot be
// probed. Permission failures (403) are only reported to members.
package workspace

import (
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
)

// Actor is the authenticated user performing an operation (see audit.Actor).
type Actor = audit.Actor

// rank orders roles: owner > admin > member.
func rank(r store.WorkspaceRole) int {
	switch r {
	case store.WorkspaceRoleOwner:
		return 3
	case store.WorkspaceRoleAdmin:
		return 2
	case store.WorkspaceRoleMember:
		return 1
	default:
		return 0
	}
}

// atLeast reports whether role r includes the permissions of min.
func atLeast(r, minRole store.WorkspaceRole) bool {
	return rank(r) >= rank(minRole)
}

// ParseRole validates a role name from user input.
func ParseRole(s string) (store.WorkspaceRole, bool) {
	r := store.WorkspaceRole(s)
	return r, r.Valid()
}
