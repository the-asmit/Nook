package api

import (
	"context"
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
	// StartupTimeoutSeconds bounds how long a new instance may take to
	// pass its health check.
	StartupTimeoutSeconds int32 `json:"startup_timeout_seconds"`
	ReadOnlyRootfs        bool  `json:"read_only_rootfs"`
	// DesiredState is "running" or "stopped".
	DesiredState string `json:"desired_state"`
	// URL is where visitors open the app (through the gateway).
	URL string `json:"url"`
	// AccessMode is workspace, restricted or public.
	AccessMode string `json:"access_mode"`
	// SleepAfter is how long the app may go without requests before it
	// sleeps ("15m"), or "never".
	SleepAfter string `json:"sleep_after"`
	// Deployments is how many deployments the app has had.
	Deployments int32     `json:"deployments"`
	CreatedAt   time.Time `json:"created_at"`
}

func (h *V1) appView(ws string, a *store.App) AppView {
	return AppView{
		URL: h.AppsBase.URL(ws, a.Slug), AccessMode: string(a.AccessMode),
		ID: a.ID, Slug: a.Slug, Name: a.Name, Port: a.Port, HealthCheckPath: a.HealthCheckPath,
		MemoryMB: a.MemoryMb, CPUMillicores: a.CpuMillicores, StartupTimeoutSeconds: a.StartupTimeoutSeconds,
		ReadOnlyRootfs: a.ReadOnlyRootfs, DesiredState: string(a.DesiredState), SleepAfter: apps.FormatSleepAfter(a.SleepAfterSeconds),
		Deployments: a.NextDeploymentNumber - 1, CreatedAt: a.CreatedAt,
	}
}

// AppDetailView is an app with what runs it.
type AppDetailView struct {
	AppView
	// LiveDeployment is the number of the deployment serving the app.
	LiveDeployment *int32 `json:"live_deployment"`
	// Health summarizes the app: "running", "starting", "unhealthy"
	// (restarting after crashes), "crashed", "sleeping", "waking",
	// "stopped" or "not_deployed".
	Health   string        `json:"health"`
	Instance *InstanceView `json:"instance"`
	// SleepingSince and SleepReason ("idle", or "evicted" to make room for
	// another app) are set while the app sleeps.
	SleepingSince *time.Time `json:"sleeping_since"`
	SleepReason   string     `json:"sleep_reason,omitempty"`
	// LastRequestAt is when the gateways last saw a request for the app.
	LastRequestAt *time.Time `json:"last_request_at"`
}

func (h *V1) appDetailView(ctx context.Context, ws string, rt *apps.Runtime) AppDetailView {
	v := AppDetailView{AppView: h.appView(ws, &rt.App), Instance: instanceView(rt.Instance), Health: "not_deployed",
		SleepingSince: rt.App.SleepingSince, SleepReason: rt.App.SleepReason, LastRequestAt: rt.App.LastRequestAt}
	if h.LastRequest != nil {
		if t := h.LastRequest(ctx, rt.App.ID); t != nil && (v.LastRequestAt == nil || t.After(*v.LastRequestAt)) {
			v.LastRequestAt = t
		}
	}
	if rt.Live != nil {
		v.LiveDeployment = &rt.Live.Number
	}
	waking := rt.App.WakeRequestedAt != nil && (rt.Instance == nil || rt.Instance.State != store.InstanceStateHealthy)
	switch {
	case rt.App.DesiredState == store.AppDesiredStateStopped:
		v.Health = "stopped"
	case rt.Live == nil:
	case rt.App.SleepingSince != nil:
		v.Health = "sleeping"
	case waking:
		v.Health = "waking"
	case rt.Instance == nil:
		v.Health = "starting"
	default:
		switch rt.Instance.State {
		case store.InstanceStateHealthy:
			v.Health = "running"
		case store.InstanceStateStarting:
			v.Health = "starting"
		case store.InstanceStateUnhealthy:
			v.Health = "unhealthy"
		case store.InstanceStateCrashed, store.InstanceStateFailed:
			v.Health = "crashed"
		default:
			v.Health = "stopped"
		}
	}
	// A running app whose database server is down cannot do its work.
	if h.Databases != nil && (v.Health == "running" || v.Health == "starting" || v.Health == "unhealthy") && h.Databases.Unavailable(ctx, rt.App.ID) {
		v.Health = "database_unavailable"
	}
	return v
}

// CreateAppRequest creates an app; omitted settings take the defaults.
type CreateAppRequest struct {
	Slug            string `json:"slug"`
	Name            string `json:"name"`
	Port            int32  `json:"port"`
	HealthCheckPath string `json:"health_check_path"`
	MemoryMB        int32  `json:"memory_mb"`
	CPUMillicores   int32  `json:"cpu_millicores"`
	// StartupTimeoutSeconds defaults to 60, up to the instance's maximum.
	StartupTimeoutSeconds int32 `json:"startup_timeout_seconds"`
	ReadOnlyRootfs        bool  `json:"read_only_rootfs"`
	// SleepAfter is a duration ("15m") or "never"; default 15m.
	SleepAfter string `json:"sleep_after"`
}

// UpdateAppRequest changes an app's settings; omitted fields stay.
type UpdateAppRequest struct {
	Port                  *int32  `json:"port"`
	HealthCheckPath       *string `json:"health_check_path"`
	MemoryMB              *int32  `json:"memory_mb"`
	CPUMillicores         *int32  `json:"cpu_millicores"`
	StartupTimeoutSeconds *int32  `json:"startup_timeout_seconds"`
	ReadOnlyRootfs        *bool   `json:"read_only_rootfs"`
	SleepAfter            *string `json:"sleep_after"`
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
	c.JSON(http.StatusOK, page(list, limit, func(a *store.App) AppView { return h.appView(c.Param("slug"), a) }, func(a *store.App) any { return slugCursor{Slug: a.Slug} }))
}

func (h *V1) createApp(c *gin.Context) {
	var req CreateAppRequest
	if !decodeJSON(c, &req) {
		return
	}
	app, err := h.Apps.Create(c.Request.Context(), actor(c), c.Param("slug"), &apps.Spec{
		Slug: req.Slug, Name: req.Name, Port: req.Port, HealthCheckPath: req.HealthCheckPath,
		MemoryMB: req.MemoryMB, CPUMillicores: req.CPUMillicores,
		StartupTimeoutSeconds: req.StartupTimeoutSeconds, ReadOnlyRootfs: req.ReadOnlyRootfs, SleepAfter: req.SleepAfter,
	})
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusCreated, h.appView(c.Param("slug"), &app))
}

func (h *V1) getApp(c *gin.Context) {
	rt, err := h.Apps.GetRuntime(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, h.appDetailView(c.Request.Context(), c.Param("slug"), &rt))
}

// wakeApp wakes a sleeping app (any member); 202 while it starts.
func (h *V1) wakeApp(c *gin.Context) {
	ctx := c.Request.Context()
	rt, err := h.Apps.GetRuntime(ctx, actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	switch {
	case rt.App.DesiredState == store.AppDesiredStateStopped:
		writeError(c, h.Logger, apperr.Conflict("app_stopped", "the app is stopped; start it with nook apps start"))
		return
	case rt.Live == nil:
		writeError(c, h.Logger, apperr.Conflict("not_deployed", "the app has not been deployed yet"))
		return
	}
	if _, err = h.Releases.WakeApp(ctx, rt.App.ID); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if rt, err = h.Apps.GetRuntime(ctx, actor(c), c.Param("slug"), c.Param("app")); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusAccepted, h.appDetailView(ctx, c.Param("slug"), &rt))
}

func (h *V1) updateApp(c *gin.Context) {
	var req UpdateAppRequest
	if !decodeJSON(c, &req) {
		return
	}
	if _, err := h.Apps.Update(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), apps.Settings{
		Port: req.Port, HealthCheckPath: req.HealthCheckPath, MemoryMB: req.MemoryMB, CPUMillicores: req.CPUMillicores,
		StartupTimeoutSeconds: req.StartupTimeoutSeconds, ReadOnlyRootfs: req.ReadOnlyRootfs, SleepAfter: req.SleepAfter,
	}); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.getApp(c)
}

func (h *V1) stopApp(c *gin.Context) {
	if _, err := h.Apps.Stop(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app")); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.getApp(c)
}

func (h *V1) startApp(c *gin.Context) {
	if _, err := h.Apps.Start(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app")); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.getApp(c)
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
	// MaxMemoryMB is optional; omitted keeps the current memory quota.
	MaxMemoryMB *int32 `json:"max_memory_mb"`
	// MaxDatabases is optional: omitted keeps the current value.
	MaxDatabases *int32 `json:"max_databases"`
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
	q, err := h.Apps.SetQuota(c.Request.Context(), actor(c), c.Param("slug"), *req.MaxApps, *req.MaxConcurrentBuilds, req.MaxMemoryMB, req.MaxDatabases)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, q)
}
