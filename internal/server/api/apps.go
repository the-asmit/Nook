package api

import (
	"net/http"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/store"
)

// AppView is an app.
type AppView struct {
	ID              uuid.UUID `json:"id"`
	Slug            string    `json:"slug"`
	Name            string    `json:"name"`
	Port            int32     `json:"port"`
	HealthCheckPath string    `json:"health_check_path"`
	MemoryMB        int32     `json:"memory_mb"`
	CPUMillicores   int32     `json:"cpu_millicores"`
	// Deployments is how many deployments the app has had.
	Deployments int32     `json:"deployments"`
	CreatedAt   time.Time `json:"created_at"`
}

func appView(a *store.App) AppView {
	return AppView{
		ID: a.ID, Slug: a.Slug, Name: a.Name, Port: a.Port, HealthCheckPath: a.HealthCheckPath,
		MemoryMB: a.MemoryMb, CPUMillicores: a.CpuMillicores, Deployments: a.NextDeploymentNumber - 1, CreatedAt: a.CreatedAt,
	}
}

// CreateAppRequest creates an app; omitted settings take the defaults.
type CreateAppRequest struct {
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	Port            int32  `json:"port"`
	HealthCheckPath string `json:"health_check_path"`
	MemoryMB        int32  `json:"memory_mb"`
	CPUMillicores   int32  `json:"cpu_millicores"`
}

type slugCursor struct {
	Slug string `json:"s"`
}

func (h *V1) listApps(c *gin.Context) {
	var cur slugCursor
	limit, err := pageParams(c, &cur)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	list, err := h.Apps.List(c.Request.Context(), actor(c), c.Param("slug"), cur.Slug, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, page(list, limit, appView, func(a *store.App) any { return slugCursor{Slug: a.Slug} }))
}

func (h *V1) createApp(c *gin.Context) {
	var req CreateAppRequest
	if !decodeJSON(c, &req) {
		return
	}
	app, err := h.Apps.Create(c.Request.Context(), actor(c), c.Param("slug"), apps.Spec{
		Slug: req.Slug, Name: req.Name, Port: req.Port, HealthCheckPath: req.HealthCheckPath,
		MemoryMB: req.MemoryMB, CPUMillicores: req.CPUMillicores,
	})
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusCreated, appView(&app))
}

func (h *V1) getApp(c *gin.Context) {
	app, err := h.Apps.Get(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, appView(&app))
}

func (h *V1) deleteApp(c *gin.Context) {
	if err := h.Apps.Delete(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app")); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// QuotaRequest sets a workspace's quota.
type QuotaRequest struct {
	MaxApps             *int32 `json:"max_apps"`
	MaxConcurrentBuilds *int32 `json:"max_concurrent_builds"`
}

func (h *V1) getQuota(c *gin.Context) {
	q, err := h.Apps.GetQuota(c.Request.Context(), c.Param("slug"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, q)
}

func (h *V1) setQuota(c *gin.Context) {
	var req QuotaRequest
	if !decodeJSON(c, &req) {
		return
	}
	if req.MaxApps == nil || req.MaxConcurrentBuilds == nil {
		writeError(c, h.Logger, apperr.Invalid("invalid_body", `"max_apps" and "max_concurrent_builds" are required`))
		return
	}
	q, err := h.Apps.SetQuota(c.Request.Context(), actor(c), c.Param("slug"), *req.MaxApps, *req.MaxConcurrentBuilds)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, q)
}
