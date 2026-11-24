package api

import (
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/device"
	"github.com/the-asmit/nook/internal/ratelimit"
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
}

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

	authed.GET("/tokens", h.listTokens)
	authed.POST("/tokens", h.createToken)
	authed.DELETE("/tokens/:token_id", h.revokeToken)
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
