package api

import (
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// The JSON shapes returned by the API. They are separate from the store
// models so that internal columns (hashes, OIDC subjects) can never leak
// by accident.

// UserView is a user.
type UserView struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	Name            string     `json:"name"`
	AvatarURL       string     `json:"avatar_url"`
	IsInstanceAdmin bool       `json:"is_instance_admin"`
	CreatedAt       time.Time  `json:"created_at"`
	LastLoginAt     *time.Time `json:"last_login_at"`
}

func userView(u *store.User) UserView {
	return UserView{
		ID: u.ID, Email: u.Email, Name: u.Name, AvatarURL: u.AvatarUrl,
		IsInstanceAdmin: u.IsInstanceAdmin, CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt,
	}
}

// WorkspaceView is a workspace with the caller's role in it.
type WorkspaceView struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Personal  bool      `json:"personal"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func workspaceView(v *workspace.View) WorkspaceView {
	return WorkspaceView{
		ID: v.Workspace.ID, Name: v.Workspace.Name, Slug: v.Workspace.Slug,
		Personal: v.Personal(), Role: string(v.Role), CreatedAt: v.Workspace.CreatedAt,
	}
}

// MemberView is a workspace member.
type MemberView struct {
	User     MemberUser `json:"user"`
	Role     string     `json:"role"`
	JoinedAt time.Time  `json:"joined_at"`
}

// MemberUser is the public part of a member's user record.
type MemberUser struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	AvatarURL string    `json:"avatar_url"`
}

func memberView(m *workspace.Member) MemberView {
	return MemberView{
		User: MemberUser{ID: m.UserID, Email: m.Email, Name: m.Name, AvatarURL: m.AvatarURL},
		Role: string(m.Role), JoinedAt: m.JoinedAt,
	}
}

// InvitationView is an open invitation.
type InvitationView struct {
	ID        uuid.UUID  `json:"id"`
	Email     string     `json:"email"`
	Role      string     `json:"role"`
	InvitedBy *uuid.UUID `json:"invited_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
}

func invitationView(i *store.Invitation) InvitationView {
	return InvitationView{
		ID: i.ID, Email: i.Email, Role: string(i.Role), InvitedBy: i.InvitedBy,
		CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt,
	}
}

// TokenView is an API token's metadata (never the token itself).
type TokenView struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

func tokenView(t *store.ApiToken) TokenView {
	return TokenView{
		ID: t.ID, Name: t.Name, Prefix: t.Prefix, CreatedAt: t.CreatedAt,
		LastUsedAt: t.LastUsedAt, ExpiresAt: t.ExpiresAt,
	}
}

// CreatedTokenView is returned once, when a token is created.
type CreatedTokenView struct {
	// Token is the secret; it is shown exactly once and cannot be retrieved later.
	Token    string    `json:"token"`
	Metadata TokenView `json:"metadata"`
}
