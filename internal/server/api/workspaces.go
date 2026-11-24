package api

import (
	"net/http"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// CreateWorkspaceRequest creates a workspace.
type CreateWorkspaceRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// UpdateWorkspaceRequest changes a workspace's name.
type UpdateWorkspaceRequest struct {
	Name string `json:"name"`
}

type workspaceCursor struct {
	Slug string `json:"s"`
}

func (h *V1) listWorkspaces(c *gin.Context) {
	var cur workspaceCursor
	limit, err := pageParams(c, &cur)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	views, err := h.Workspaces.List(c.Request.Context(), actor(c), cur.Slug, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, page(views, limit, workspaceView, func(v *workspace.View) any {
		return workspaceCursor{Slug: v.Workspace.Slug}
	}))
}

func (h *V1) createWorkspace(c *gin.Context) {
	var req CreateWorkspaceRequest
	if !decodeJSON(c, &req) {
		return
	}
	v, err := h.Workspaces.Create(c.Request.Context(), actor(c), req.Name, req.Slug)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusCreated, workspaceView(&v))
}

func (h *V1) getWorkspace(c *gin.Context) {
	v, err := h.Workspaces.Get(c.Request.Context(), actor(c), c.Param("slug"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, workspaceView(&v))
}

func (h *V1) updateWorkspace(c *gin.Context) {
	var req UpdateWorkspaceRequest
	if !decodeJSON(c, &req) {
		return
	}
	v, err := h.Workspaces.Rename(c.Request.Context(), actor(c), c.Param("slug"), req.Name)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, workspaceView(&v))
}

func (h *V1) deleteWorkspace(c *gin.Context) {
	if err := h.Workspaces.Delete(c.Request.Context(), actor(c), c.Param("slug")); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

type memberCursor struct {
	Email string    `json:"e"`
	ID    uuid.UUID `json:"i"`
}

func (h *V1) listMembers(c *gin.Context) {
	var cur memberCursor
	limit, err := pageParams(c, &cur)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	members, err := h.Workspaces.ListMembers(c.Request.Context(), actor(c), c.Param("slug"),
		workspace.MemberCursor{Email: cur.Email, UserID: cur.ID}, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, page(members, limit, memberView, func(m *workspace.Member) any {
		return memberCursor{Email: m.Email, ID: m.UserID}
	}))
}

// UpdateMemberRequest changes a member's role.
type UpdateMemberRequest struct {
	Role string `json:"role"`
}

func (h *V1) updateMember(c *gin.Context) {
	var req UpdateMemberRequest
	if !decodeJSON(c, &req) {
		return
	}
	target, err := pathUUID(c, "user_id")
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if err := h.Workspaces.ChangeRole(c.Request.Context(), actor(c), c.Param("slug"), target, store.WorkspaceRole(req.Role)); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *V1) removeMember(c *gin.Context) {
	target, err := pathUUID(c, "user_id")
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if err := h.Workspaces.RemoveMember(c.Request.Context(), actor(c), c.Param("slug"), target); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// CreateInvitationRequest invites someone to a workspace.
type CreateInvitationRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type idCursor struct {
	ID uuid.UUID `json:"i"`
}

func (h *V1) listInvitations(c *gin.Context) {
	var cur idCursor
	limit, err := pageParams(c, &cur)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	inv, err := h.Workspaces.ListInvitations(c.Request.Context(), actor(c), c.Param("slug"), cur.ID, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, page(inv, limit, invitationView, func(i *store.Invitation) any {
		return idCursor{ID: i.ID}
	}))
}

func (h *V1) createInvitation(c *gin.Context) {
	var req CreateInvitationRequest
	if !decodeJSON(c, &req) {
		return
	}
	if req.Role == "" {
		req.Role = string(store.WorkspaceRoleMember)
	}
	inv, err := h.Workspaces.Invite(c.Request.Context(), actor(c), c.Param("slug"), req.Email, store.WorkspaceRole(req.Role))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusCreated, invitationView(&inv))
}

func (h *V1) revokeInvitation(c *gin.Context) {
	id, err := pathUUID(c, "invitation_id")
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if err := h.Workspaces.RevokeInvitation(c.Request.Context(), actor(c), c.Param("slug"), id); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}
