// Package audit records security-relevant actions in the append-only
// audit_log table. Entries are written in the same transaction as the
// change they describe, so a change is never committed without its record.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"uuid"

	"github.com/the-asmit/nook/internal/store"
)

// Action names. They are part of the audit log's contract: never rename
// one, add a new one instead.
const (
	ActionUserCreate         = "user.create"
	ActionSignIn             = "auth.sign_in"
	ActionSignOut            = "auth.sign_out"
	ActionTokenCreate        = "token.create"
	ActionTokenRevoke        = "token.revoke"
	ActionDeviceApprove      = "device.approve"
	ActionDeviceDeny         = "device.deny"
	ActionWorkspaceCreate    = "workspace.create"
	ActionWorkspaceUpdate    = "workspace.update"
	ActionWorkspaceDelete    = "workspace.delete"
	ActionMemberRoleChange   = "member.role_change"
	ActionMemberRemove       = "member.remove"
	ActionInvitationCreate   = "invitation.create"
	ActionInvitationRevoke   = "invitation.revoke"
	ActionInvitationAccept   = "invitation.accept"
	ActionInstanceAdminGrant = "user.instance_admin_grant"
	ActionUserDisable        = "user.disable"
	ActionUserEnable         = "user.enable"
	ActionNodeJoin           = "node.join"
	ActionNodeDrain          = "node.drain"
	ActionNodeUndrain        = "node.undrain"
	ActionNodeRemove         = "node.remove"
	ActionNodeCertRenew      = "node.certificate_renew"
	ActionJoinTokenCreate    = "join_token.create" //nolint:gosec // G101: an action name, not a credential.
	ActionJoinTokenRevoke    = "join_token.revoke" //nolint:gosec // G101: an action name, not a credential.
	ActionAppCreate          = "app.create"
	ActionAppDelete          = "app.delete"
	ActionDeploymentCreate   = "deployment.create"
	ActionDeploymentCancel   = "deployment.cancel"
	ActionQuotaUpdate        = "quota.update"
	ActionAppUpdate          = "app.update"
	ActionAppStop            = "app.stop"
	ActionAppStart           = "app.start"
	ActionEnvSet             = "env.set"
	ActionEnvUnset           = "env.unset"
	ActionDeploymentRollback = "deployment.rollback"
	ActionSecretsRotate      = "secrets.rotate_key"
	ActionAccessSetMode      = "access.set_mode"
	ActionAccessGrant        = "access.grant"
	ActionAccessRevoke       = "access.revoke"
	ActionVisitorSignIn      = "visitor.sign_in"
)

// Target types.
const (
	TargetUser       = "user"
	TargetSession    = "session"
	TargetAPIToken   = "api_token"
	TargetDevice     = "device_authorization"
	TargetWorkspace  = "workspace"
	TargetMembership = "membership"
	TargetInvitation = "invitation"
	TargetNode       = "node"
	TargetJoinToken  = "join_token"
	TargetApp        = "app"
	TargetDeployment = "deployment"
)

// Actor is the authenticated user performing an action, plus the request
// metadata recorded with it.
type Actor struct {
	UserID uuid.UUID
	IP     *netip.Addr
}

// Entry describes one action. Metadata must never contain secrets (tokens,
// codes, passwords); it is stored as JSON and readable by administrators.
type Entry struct {
	WorkspaceID *uuid.UUID
	ActorID     *uuid.UUID
	Action      string
	TargetType  string
	TargetID    string
	Metadata    map[string]any
	IP          *netip.Addr
}

// Record writes entry using q, which should be the transaction carrying
// the change being audited.
func Record(ctx context.Context, q *store.Queries, e *Entry) error {
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encode audit metadata: %w", err)
	}
	err = q.InsertAuditEntry(ctx, store.InsertAuditEntryParams{
		WorkspaceID: e.WorkspaceID,
		ActorUserID: e.ActorID,
		Action:      e.Action,
		TargetType:  e.TargetType,
		TargetID:    e.TargetID,
		Metadata:    raw,
		Ip:          e.IP,
	})
	if err != nil {
		return fmt.Errorf("write audit entry %s: %w", e.Action, err)
	}
	return nil
}

// Ptr returns a pointer to id, for the optional ID fields of Entry.
func Ptr(id uuid.UUID) *uuid.UUID {
	return &id
}
