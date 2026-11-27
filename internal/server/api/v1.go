package api

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/agentlink"
	"github.com/the-asmit/nook/internal/appdb"
	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/builds"
	"github.com/the-asmit/nook/internal/device"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/ratelimit"
	"github.com/the-asmit/nook/internal/rollout"
	"github.com/the-asmit/nook/internal/routes"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// Rate limits on the unauthenticated device-flow endpoints, per client IP.
var (
	// A CLI starts one flow per login; ten a minute absorbs retries and a
	// handful of people behind one NAT.
	deviceStartRule = ratelimit.Rule{Name: "device_start", Limit: 10, Window: time.Minute}
	// One CLI polls every 5 s (12 a minute); sixty allows several at once
	// from one address while making device-code guessing pointless.
	devicePollRule = ratelimit.Rule{Name: "device_poll", Limit: 60, Window: time.Minute}
)

// V1Deps are the collaborators of the /api/v1 handlers.
type V1Deps struct {
	Logger     *slog.Logger
	Store      *store.Store
	Auth       *auth.Authenticator
	Tokens     *auth.APITokens
	Workspaces *workspace.Service
	Devices    *device.Service
	Limiter    *ratelimit.Limiter
	// VerificationURL is where people approve device codes (public URL + /device).
	VerificationURL string
	Admin           *identity.Admin
	Nodes           *nodes.Registry
	Hub             *agentlink.Hub
	// AgentServer and CAHash go into the join command shown to admins.
	AgentServer string
	CAHash      string
	Apps        *apps.Service
	Logs        *builds.Logs
	AppLogs     *rollout.LogStreams
	GCWindow    *builds.GCWindow
	// RegistryGCSecret authenticates the registry's garbage-collection job.
	RegistryGCSecret config.Secret
	// RegistryAddr is the registry host:port images are referenced by.
	RegistryAddr   string
	MaxSourceBytes int64
	// AppsBase builds app URLs.
	AppsBase routes.Base
	// Releases wakes sleeping apps (`nook apps wake`).
	Releases *rollout.Controller
	// LastRequest returns when an app last received a request (gateway
	// activity), or nil.
	LastRequest func(ctx context.Context, app uuid.UUID) *time.Time
	// Databases manages app databases.
	Databases *appdb.Controller
}

// RouteBuildLog streams build logs; it is exempt from the request timeout.
const RouteBuildLog = "/api/v1/workspaces/:slug/apps/:app/deployments/:number/build-log"

// V1 serves the JSON API.
type V1 struct {
	V1Deps
}

// RegisterV1 mounts the /api/v1 routes on r.
func RegisterV1(r gin.IRouter, d *V1Deps) {
	h := &V1{V1Deps: *d}
	v1 := r.Group("/api/v1")
	v1.POST("/auth/device", h.deviceStart)
	v1.POST("/auth/device/token", h.deviceToken)

	authed := v1.Group("", h.Auth.RequireAPI())
	authed.GET("/me", h.me)
	authed.POST("/auth/logout", h.logout)

	authed.GET("/workspaces", h.listWorkspaces)
	authed.POST("/workspaces", h.createWorkspace)
	authed.GET("/workspaces/:slug", h.getWorkspace)
	authed.PATCH("/workspaces/:slug", h.updateWorkspace)
	authed.DELETE("/workspaces/:slug", h.deleteWorkspace)

	authed.GET("/workspaces/:slug/members", h.listMembers)
	authed.PATCH("/workspaces/:slug/members/:user_id", h.updateMember)
	authed.DELETE("/workspaces/:slug/members/:user_id", h.removeMember)

	authed.GET("/workspaces/:slug/invitations", h.listInvitations)
	authed.POST("/workspaces/:slug/invitations", h.createInvitation)
	authed.DELETE("/workspaces/:slug/invitations/:invitation_id", h.revokeInvitation)

	appRoutes := authed.Group("/workspaces/:slug/apps")
	appRoutes.GET("", h.listApps)
	appRoutes.POST("", h.createApp)
	appRoutes.GET("/:app", h.getApp)
	appRoutes.PATCH("/:app", h.updateApp)
	appRoutes.DELETE("/:app", h.deleteApp)
	appRoutes.POST("/:app/stop", h.stopApp)
	appRoutes.POST("/:app/start", h.startApp)
	appRoutes.POST("/:app/wake", h.wakeApp)
	appRoutes.POST("/:app/rollback", h.rollback)
	appRoutes.GET("/:app/logs", h.appLogs)
	appRoutes.GET("/:app/env", h.listEnv)
	appRoutes.PUT("/:app/env", h.setEnv)
	appRoutes.DELETE("/:app/env/:key", h.unsetEnv)
	appRoutes.GET("/:app/access", h.getAccess)
	appRoutes.PUT("/:app/access", h.setAccess)
	appRoutes.POST("/:app/access/grants", h.grantAccess)
	appRoutes.DELETE("/:app/access/grants/:email", h.revokeAccess)
	appRoutes.GET("/:app/deployments", h.listDeployments)
	appRoutes.POST("/:app/deployments", h.createDeployment)
	appRoutes.GET("/:app/deployments/:number", h.getDeployment)
	appRoutes.POST("/:app/deployments/:number/upload-complete", h.confirmUpload)
	appRoutes.POST("/:app/deployments/:number/cancel", h.cancelDeployment)
	appRoutes.GET("/:app/deployments/:number/build-log", h.buildLog)
	appRoutes.GET("/:app/database", h.getDatabase)
	appRoutes.POST("/:app/database", h.createDatabase)
	appRoutes.DELETE("/:app/database", h.deleteDatabase)
	appRoutes.POST("/:app/database/rotate-password", h.rotateDatabasePassword)
	appRoutes.POST("/:app/database/dumps", h.createDatabaseDump)
	appRoutes.GET("/:app/database/dumps/:dump", h.getDatabaseDump)

	// The registry's GC job uses BusyBox wget, which only sends GET and POST.
	gc := v1.Group("/registry/gc-window", h.requireGCSecret)
	gc.POST("/open", h.openGCWindow)
	gc.POST("/close", h.closeGCWindow)

	authed.GET("/tokens", h.listTokens)
	authed.POST("/tokens", h.createToken)
	authed.DELETE("/tokens/:token_id", h.revokeToken)

	admin := authed.Group("", h.requireInstanceAdmin)
	admin.GET("/admin/users", h.listUsers)
	admin.PATCH("/admin/users/:user_id", h.updateUser)

	admin.GET("/nodes", h.listNodes)
	admin.GET("/nodes/:node", h.getNode)
	admin.POST("/nodes/:node/inspect", h.inspectNode)
	admin.POST("/nodes/:node/drain", h.setDraining(true))
	admin.POST("/nodes/:node/undrain", h.setDraining(false))
	admin.DELETE("/nodes/:node", h.removeNode)
	admin.PUT("/nodes/:node/labels", h.setNodeLabels)
	admin.GET("/admin/database", h.databaseStatus)
	admin.POST("/admin/database/failover", h.databaseFailover)
	admin.DELETE("/admin/database/servers/:server", h.removeDatabaseServer)

	admin.GET("/admin/workspaces/:slug/quota", h.getQuota)
	admin.PUT("/admin/workspaces/:slug/quota", h.setQuota)

	admin.GET("/join-tokens", h.listJoinTokens)
	admin.POST("/join-tokens", h.createJoinToken)
	admin.DELETE("/join-tokens/:token_id", h.revokeJoinToken)
}

// principal returns the authenticated caller; RequireAPI guarantees it.
func principal(c *gin.Context) *auth.Principal {
	p, _ := auth.PrincipalFrom(c.Request.Context())
	return p
}

// clientIP returns the caller's address for audit and rate limiting.
func clientIP(c *gin.Context) *netip.Addr {
	addr, err := netip.ParseAddr(c.ClientIP())
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	return &addr
}

func actor(c *gin.Context) workspace.Actor {
	return workspace.Actor{UserID: principal(c).User.ID, IP: clientIP(c)}
}

// allow applies a per-IP rate limit and writes the 429 itself when the
// limit is exceeded.
func (h *V1) allow(c *gin.Context, rule ratelimit.Rule) bool {
	key := c.ClientIP()
	res, err := h.Limiter.Allow(c.Request.Context(), rule, key)
	if err != nil {
		writeError(c, h.Logger, err)
		return false
	}
	if !res.Allowed {
		c.Header("Retry-After", strconv.Itoa(int(math.Ceil(res.RetryAfter.Seconds()))))
		writeError(c, h.Logger, apperr.RateLimited("too many requests; retry later"))
		return false
	}
	return true
}

// MeResponse describes the caller.
type MeResponse struct {
	User UserView `json:"user"`
	// AuthMethod is "session" or "token".
	AuthMethod string `json:"auth_method"`
	// CSRFToken must be sent as X-CSRF-Token on state-changing requests
	// made with the session cookie. Absent for token authentication.
	CSRFToken string `json:"csrf_token,omitempty"`
}

func (h *V1) me(c *gin.Context) {
	p := principal(c)
	c.JSON(http.StatusOK, MeResponse{User: userView(&p.User), AuthMethod: string(p.Method), CSRFToken: p.CSRFToken})
}

func (h *V1) logout(c *gin.Context) {
	p := principal(c)
	if err := auth.Logout(c.Request.Context(), h.Store, p, clientIP(c)); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if p.Method == auth.MethodSession {
		h.Auth.Site().ClearCookie(c.Writer, auth.SessionCookie)
	}
	c.Status(http.StatusNoContent)
}

// DeviceStartRequest starts a CLI login.
type DeviceStartRequest struct {
	// ClientName is shown on the approval page, e.g. "nook CLI on laptop".
	ClientName string `json:"client_name"`
}

// DeviceStartResponse follows RFC 8628 section 3.2.
type DeviceStartResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (h *V1) deviceStart(c *gin.Context) {
	if !h.allow(c, deviceStartRule) {
		return
	}
	var req DeviceStartRequest
	if !decodeJSON(c, &req) {
		return
	}
	started, err := h.Devices.Start(c.Request.Context(), req.ClientName)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, DeviceStartResponse{
		DeviceCode:              started.DeviceCode,
		UserCode:                started.UserCode,
		VerificationURI:         h.VerificationURL,
		VerificationURIComplete: h.VerificationURL + "?user_code=" + started.UserCode,
		ExpiresIn:               int(started.ExpiresIn.Seconds()),
		Interval:                int(started.Interval.Seconds()),
	})
}

// DeviceTokenRequest polls for the result of a CLI login.
type DeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
}

// DeviceTokenResponse carries the issued API token.
type DeviceTokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	Token       TokenView `json:"token"`
}

func (h *V1) deviceToken(c *gin.Context) {
	if !h.allow(c, devicePollRule) {
		return
	}
	var req DeviceTokenRequest
	if !decodeJSON(c, &req) {
		return
	}
	issued, err := h.Devices.Poll(c.Request.Context(), req.DeviceCode)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, DeviceTokenResponse{AccessToken: issued.Token, TokenType: "Bearer", Token: tokenView(&issued.APIToken)})
}
