package api

import (
	"net/http"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/store"
)

// requireInstanceAdmin rejects callers who are not instance administrators.
// These endpoints manage the installation itself, so 403 (not 404) is
// fine: their existence is no secret.
func (h *V1) requireInstanceAdmin(c *gin.Context) {
	if !principal(c).User.IsInstanceAdmin {
		writeError(c, h.Logger, errForbiddenAdmin)
		return
	}
	c.Next()
}

// AdminUserView is a user as instance administrators see it.
type AdminUserView struct {
	UserView
	DisabledAt *time.Time `json:"disabled_at"`
}

func adminUserView(u *store.User) AdminUserView {
	return AdminUserView{UserView: userView(u), DisabledAt: u.DisabledAt}
}

type emailCursor struct {
	Email string `json:"e"`
}

func (h *V1) listUsers(c *gin.Context) {
	var cur emailCursor
	limit, err := pageParams(c, &cur)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	email := c.Query("email")
	if len(email) > 254 {
		writeError(c, h.Logger, errInvalidEmailFilter)
		return
	}
	users, err := h.Admin.ListUsers(c.Request.Context(), cur.Email, email, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, page(users, limit, adminUserView, func(u *store.User) any { return emailCursor{Email: u.Email} }))
}

// UpdateUserRequest changes a user's account state.
type UpdateUserRequest struct {
	// Disabled true disables the user and revokes all their sessions and
	// tokens; false re-enables them.
	Disabled *bool `json:"disabled"`
}

func (h *V1) updateUser(c *gin.Context) {
	var req UpdateUserRequest
	if !decodeJSON(c, &req) {
		return
	}
	if req.Disabled == nil {
		writeError(c, h.Logger, errMissingDisabled)
		return
	}
	id, err := pathUUID(c, "user_id")
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	u, err := h.Admin.SetDisabled(c.Request.Context(), actor(c), id, *req.Disabled)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, adminUserView(&u))
}

// JoinTokenView is a join token's metadata (never the token itself).
type JoinTokenView struct {
	ID         uuid.UUID  `json:"id"`
	Prefix     string     `json:"prefix"`
	MaxUses    int32      `json:"max_uses"`
	Uses       int32      `json:"uses"`
	CreatedBy  *uuid.UUID `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

func joinTokenView(t *store.JoinToken) JoinTokenView {
	return JoinTokenView{
		ID: t.ID, Prefix: t.Prefix, MaxUses: t.MaxUses, Uses: t.Uses, CreatedBy: t.CreatedBy,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, RevokedAt: t.RevokedAt,
	}
}

// CreateJoinTokenRequest creates a join token.
type CreateJoinTokenRequest struct {
	// MaxUses is how many nodes may join with the token (default 1).
	MaxUses *int32 `json:"max_uses"`
	// ExpiresInSeconds sets the lifetime (default 3600, at most 7 days).
	ExpiresInSeconds *int64 `json:"expires_in_seconds"`
}

// CreatedJoinTokenView is returned once, when a join token is created.
type CreatedJoinTokenView struct {
	Token string `json:"token"`
	// Server and CAHash are what the agent needs besides the token.
	Server string `json:"server"`
	CAHash string `json:"ca_hash"`
	// JoinCommand is ready to run on the new node.
	JoinCommand string        `json:"join_command"`
	Metadata    JoinTokenView `json:"metadata"`
}

func (h *V1) createJoinToken(c *gin.Context) {
	var req CreateJoinTokenRequest
	if !decodeJSON(c, &req) {
		return
	}
	var maxUses int32
	if req.MaxUses != nil {
		if *req.MaxUses < 1 {
			writeError(c, h.Logger, errInvalidMaxUses)
			return
		}
		maxUses = *req.MaxUses
	}
	var ttl time.Duration
	if req.ExpiresInSeconds != nil {
		if *req.ExpiresInSeconds < 60 || *req.ExpiresInSeconds > int64((7*24*time.Hour).Seconds()) {
			writeError(c, h.Logger, errInvalidExpiry)
			return
		}
		ttl = time.Duration(*req.ExpiresInSeconds) * time.Second
	}
	raw, tok, err := h.Nodes.CreateJoinToken(c.Request.Context(), actor(c), maxUses, ttl)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusCreated, CreatedJoinTokenView{
		Token: raw, Server: h.AgentServer, CAHash: h.CAHash,
		JoinCommand: "nook-agent join --server " + h.AgentServer + " --token " + raw + " --ca-hash " + h.CAHash,
		Metadata:    joinTokenView(&tok),
	})
}

func (h *V1) listJoinTokens(c *gin.Context) {
	var cur idCursor
	limit, err := pageParams(c, &cur)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	before := cur.ID
	if before == (uuid.UUID{}) {
		before = maxUUID
	}
	toks, err := h.Nodes.ListJoinTokens(c.Request.Context(), before, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, page(toks, limit, joinTokenView, func(t *store.JoinToken) any { return idCursor{ID: t.ID} }))
}

func (h *V1) revokeJoinToken(c *gin.Context) {
	id, err := pathUUID(c, "token_id")
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if err := h.Nodes.RevokeJoinToken(c.Request.Context(), actor(c), id); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}
