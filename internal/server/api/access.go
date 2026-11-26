package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/store"
)

// AccessView is who may open an app.
type AccessView struct {
	// Mode is the configured mode; Effective is what applies (public
	// falls back to workspace where the instance forbids public apps).
	Mode          string      `json:"mode"`
	Effective     string      `json:"effective"`
	PublicAllowed bool        `json:"public_allowed"`
	Grants        []GrantView `json:"grants"`
}

// GrantView is one email granted access.
type GrantView struct {
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func accessView(a *apps.Access) AccessView {
	v := AccessView{Mode: string(a.Mode), Effective: a.Effective, PublicAllowed: a.PublicAllowed, Grants: make([]GrantView, 0, len(a.Grants))}
	for _, g := range a.Grants {
		v.Grants = append(v.Grants, GrantView{Email: g.Email, CreatedAt: g.CreatedAt})
	}
	return v
}

// SetAccessRequest sets the access mode.
type SetAccessRequest struct {
	Mode string `json:"mode"`
}

// GrantRequest grants access to emails.
type GrantRequest struct {
	Emails []string `json:"emails"`
}

func (h *V1) getAccess(c *gin.Context) {
	a, err := h.Apps.GetAccess(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, accessView(&a))
}

func (h *V1) setAccess(c *gin.Context) {
	var req SetAccessRequest
	if !decodeJSON(c, &req) {
		return
	}
	a, err := h.Apps.SetAccessMode(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), store.AppAccessMode(req.Mode))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, accessView(&a))
}

func (h *V1) grantAccess(c *gin.Context) {
	var req GrantRequest
	if !decodeJSON(c, &req) {
		return
	}
	a, err := h.Apps.Grant(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), req.Emails)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, accessView(&a))
}

func (h *V1) revokeAccess(c *gin.Context) {
	a, err := h.Apps.Revoke(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), c.Param("email"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, accessView(&a))
}
