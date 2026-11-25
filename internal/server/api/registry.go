package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/builds"
)

// GCWindowRequest opens a registry maintenance window.
type GCWindowRequest struct {
	// TTLSeconds is the window length (60 to 1800).
	TTLSeconds int `json:"ttl_seconds"`
}

// requireGCSecret authenticates the registry's garbage-collection job by
// the shared secret NOOK_REGISTRY_GC_SECRET, compared in constant time.
func (h *V1) requireGCSecret(c *gin.Context) {
	token, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
	secret := h.RegistryGCSecret.Reveal()
	if !ok || secret == "" || subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
		writeError(c, h.Logger, apperr.Unauthenticated("a valid registry maintenance secret is required"))
		return
	}
	c.Next()
}

func (h *V1) openGCWindow(c *gin.Context) {
	var req GCWindowRequest
	if !decodeJSON(c, &req) {
		return
	}
	if req.TTLSeconds < 60 || time.Duration(req.TTLSeconds)*time.Second > builds.MaxGCWindow {
		writeError(c, h.Logger, apperr.Invalid("invalid_ttl", "ttl_seconds must be between 60 and %d", int(builds.MaxGCWindow.Seconds())))
		return
	}
	if err := h.GCWindow.Open(c.Request.Context(), time.Duration(req.TTLSeconds)*time.Second); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.Logger.InfoContext(c.Request.Context(), "registry maintenance window opened", "ttl_seconds", req.TTLSeconds)
	c.JSON(http.StatusOK, gin.H{"ttl_seconds": req.TTLSeconds})
}

func (h *V1) closeGCWindow(c *gin.Context) {
	h.GCWindow.Close(c.Request.Context())
	h.Logger.InfoContext(c.Request.Context(), "registry maintenance window closed")
	c.Status(http.StatusNoContent)
}
