package api

import (
	"net/http"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/store"
)

// CreateTokenRequest creates an API token for scripts and CI.
type CreateTokenRequest struct {
	Name string `json:"name"`
	// ExpiresInDays sets an expiry (1 to 366 days); omit for a token that
	// never expires.
	ExpiresInDays *int `json:"expires_in_days"`
}

// maxUUID sorts after every real UUID, so the first page of a newest-first
// listing starts below it.
var maxUUID = uuid.Max()

func (h *V1) listTokens(c *gin.Context) {
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
	toks, err := h.Tokens.List(c.Request.Context(), principal(c).User.ID, before, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, page(toks, limit, tokenView, func(t *store.ApiToken) any {
		return idCursor{ID: t.ID}
	}))
}

func (h *V1) createToken(c *gin.Context) {
	var req CreateTokenRequest
	if !decodeJSON(c, &req) {
		return
	}
	var lifetime *time.Duration
	if req.ExpiresInDays != nil {
		if *req.ExpiresInDays < 1 || *req.ExpiresInDays > 366 {
			writeError(c, h.Logger, apperr.Invalid("invalid_expiry", "expires_in_days must be between 1 and 366"))
			return
		}
		d := time.Duration(*req.ExpiresInDays) * 24 * time.Hour
		lifetime = &d
	}
	raw, tok, err := h.Tokens.CreateForUser(c.Request.Context(), principal(c).User.ID, clientIP(c), req.Name, lifetime)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusCreated, CreatedTokenView{Token: raw, Metadata: tokenView(&tok)})
}

func (h *V1) revokeToken(c *gin.Context) {
	id, err := pathUUID(c, "token_id")
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if err := h.Tokens.Revoke(c.Request.Context(), principal(c).User.ID, clientIP(c), id); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}
