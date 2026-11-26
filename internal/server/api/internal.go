package api

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/rollout"
	"github.com/the-asmit/nook/internal/routes"
	"github.com/the-asmit/nook/internal/visitor"
)

// The internal API serves the gateways: routes, waking sleeping apps,
// visitor sessions and the certificates they obtain. Gateways authenticate with a shared secret
// (Authorization: Bearer <NOOK_GATEWAY_SECRET>); anything else gets 404,
// so the API does not reveal itself.

// InternalDeps are the collaborators of the internal API.
type InternalDeps struct {
	Logger        *slog.Logger
	Visitors      *visitor.Service
	GatewaySecret config.Secret
	// Releases wakes sleeping apps.
	Releases *rollout.Controller
}

// maxCertificateBytes bounds a stored certificate.
const maxCertificateBytes = 64 << 10

type internalAPI struct {
	InternalDeps
}

// RegisterInternal mounts /internal/v1 on r.
func RegisterInternal(r gin.IRouter, d *InternalDeps) {
	h := &internalAPI{InternalDeps: *d}
	g := r.Group("/internal/v1", h.requireGateway)
	g.GET("/routes", h.listRoutes)
	g.GET("/routes/:app_id", h.getRoute)
	g.GET("/tls/hosts/:host", h.knownHost)
	g.POST("/apps/:app_id/wake", h.wakeApp)
	g.POST("/visitor/exchange", h.exchange)
	g.POST("/visitor/check", h.check)
	g.POST("/visitor/sign-out", h.signOut)
	g.GET("/certificates/:name", h.getCertificate)
	g.PUT("/certificates/:name", h.putCertificate)
	g.DELETE("/certificates/:name", h.deleteCertificate)
}

func (h *internalAPI) requireGateway(c *gin.Context) {
	token, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(h.GatewaySecret.Reveal())) != 1 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Next()
}

// WakeResponse tells a gateway what its wake request found: "waking" (it
// woke the app) or "awake" (already awake or being woken).
type WakeResponse struct {
	State string `json:"state"`
}

func (h *internalAPI) wakeApp(c *gin.Context) {
	id, err := uuid.Parse(c.Param("app_id"))
	if err != nil {
		writeError(c, h.Logger, apperr.NotFound("app not found"))
		return
	}
	state, err := h.Releases.WakeApp(c.Request.Context(), id)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusAccepted, WakeResponse{State: string(state)})
}

// RouteList is every app's route.
type RouteList struct {
	Routes []routes.Route `json:"routes"`
}

func (h *internalAPI) listRoutes(c *gin.Context) {
	list, err := h.Visitors.Routes(c.Request.Context())
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, RouteList{Routes: list})
}

func (h *internalAPI) getRoute(c *gin.Context) {
	id, err := uuid.Parse(c.Param("app_id"))
	if err != nil {
		writeError(c, h.Logger, apperr.NotFound("route not found"))
		return
	}
	r, err := h.Visitors.Route(c.Request.Context(), id)
	if errors.Is(err, routes.ErrNotFound) {
		writeError(c, h.Logger, apperr.NotFound("route not found"))
		return
	}
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, r)
}

func (h *internalAPI) knownHost(c *gin.Context) {
	ok, err := h.Visitors.KnownHost(c.Request.Context(), strings.ToLower(c.Param("host")))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if !ok {
		writeError(c, h.Logger, apperr.NotFound("unknown host"))
		return
	}
	c.Status(http.StatusNoContent)
}

// ExchangeRequest redeems an auth-host code on an app host.
type ExchangeRequest struct {
	Code string `json:"code"`
	Host string `json:"host"`
}

// ExchangeResponse is the app host's new session.
type ExchangeResponse struct {
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
	ReturnPath string    `json:"return_path"`
}

func (h *internalAPI) exchange(c *gin.Context) {
	var req ExchangeRequest
	if !decodeJSON(c, &req) {
		return
	}
	sess, ret, err := h.Visitors.Exchange(c.Request.Context(), req.Code, strings.ToLower(req.Host))
	if errors.Is(err, visitor.ErrInvalid) {
		writeError(c, h.Logger, apperr.Invalid("invalid_code", "the sign-in code is invalid, expired or already used"))
		return
	}
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, ExchangeResponse{Token: sess.Token, ExpiresAt: sess.ExpiresAt, ReturnPath: ret})
}

// CheckRequest checks an app host's session.
type CheckRequest struct {
	Token string `json:"token"`
	Host  string `json:"host"`
}

// CheckResponse says whether the visitor may proceed: "ok", "denied" (a
// valid session without access) or "invalid".
type CheckResponse struct {
	Status string `json:"status"`
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
}

func (h *internalAPI) check(c *gin.Context) {
	var req CheckRequest
	if !decodeJSON(c, &req) {
		return
	}
	res, err := h.Visitors.Check(c.Request.Context(), req.Token, strings.ToLower(req.Host))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, CheckResponse{Status: res.Status, Email: res.Email, Name: res.Name})
}

// SignOutRequest revokes a session.
type SignOutRequest struct {
	Token string `json:"token"`
}

func (h *internalAPI) signOut(c *gin.Context) {
	var req SignOutRequest
	if !decodeJSON(c, &req) {
		return
	}
	if err := h.Visitors.SignOut(c.Request.Context(), req.Token); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Certificate is a stored certificate or ACME account key (PEM).
type Certificate struct {
	Data []byte `json:"data"`
}

func (h *internalAPI) getCertificate(c *gin.Context) {
	data, err := h.Visitors.GetCertificate(c.Request.Context(), c.Param("name"))
	if errors.Is(err, visitor.ErrNoCertificate) {
		writeError(c, h.Logger, apperr.NotFound("no such certificate"))
		return
	}
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, Certificate{Data: data})
}

func (h *internalAPI) putCertificate(c *gin.Context) {
	if !visitor.ValidCertName(c.Param("name")) {
		writeError(c, h.Logger, apperr.Invalid("invalid_name", "invalid certificate name"))
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2*maxCertificateBytes)
	var req Certificate
	if !decodeJSON(c, &req) {
		return
	}
	if len(req.Data) == 0 || len(req.Data) > maxCertificateBytes {
		writeError(c, h.Logger, apperr.Invalid("invalid_certificate", "a certificate must be 1 to %d bytes", maxCertificateBytes))
		return
	}
	if err := h.Visitors.PutCertificate(c.Request.Context(), c.Param("name"), req.Data); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *internalAPI) deleteCertificate(c *gin.Context) {
	if err := h.Visitors.DeleteCertificate(c.Request.Context(), c.Param("name")); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}
