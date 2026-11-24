package web

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/ratelimit"
)

// userCodeRule limits how many codes one signed-in user may try. With
// 20^8 possible codes, ten guesses per ten minutes makes guessing someone
// else's pending code hopeless.
var userCodeRule = ratelimit.Rule{Name: "device_user_code", Limit: 10, Window: 10 * time.Minute}

type devicePage struct {
	pageData
	UserCode string
	Error    string
}

type deviceConfirmPage struct {
	pageData
	UserCode    string
	ClientName  string
	RequestedAt string
}

// devicePage shows the code entry form; the code from
// verification_uri_complete is pre-filled but never auto-submitted, so the
// person always confirms what they approve.
func (h *Handlers) devicePage(c *gin.Context) {
	p := h.requireUser(c)
	if p == nil {
		return
	}
	code := c.Query("user_code")
	if norm, err := auth.NormalizeUserCode(code); err == nil {
		code = auth.FormatUserCode(norm)
	} else {
		code = ""
	}
	h.render(c, http.StatusOK, "device", devicePage{
		pageData: pageData{Title: "Connect a device", User: &p.User, CSRFToken: p.CSRFToken},
		UserCode: code,
	})
}

// allowCodeAttempt applies the per-user rate limit and renders the error
// page itself when the limit is exceeded.
func (h *Handlers) allowCodeAttempt(c *gin.Context, p *auth.Principal) bool {
	res, err := h.Limiter.Allow(c.Request.Context(), userCodeRule, p.User.ID.String())
	if err != nil {
		h.Logger.ErrorContext(c.Request.Context(), "rate limit", "error", err.Error())
		h.message(c, http.StatusInternalServerError, "Something went wrong", "Please try again in a moment.", false)
		return false
	}
	if !res.Allowed {
		h.message(c, http.StatusTooManyRequests, "Too many attempts",
			"You have entered too many codes. Wait a few minutes and try again.", false)
		return false
	}
	return true
}

// deviceLookup shows the confirmation page for a typed code.
func (h *Handlers) deviceLookup(c *gin.Context) {
	p := h.requireUser(c)
	if p == nil || !h.csrfOK(c, p) || !h.allowCodeAttempt(c, p) {
		return
	}
	typed := c.PostForm("user_code")
	d, err := h.Devices.Lookup(c.Request.Context(), typed)
	if err != nil {
		h.deviceError(c, p, typed, err)
		return
	}
	h.render(c, http.StatusOK, "device_confirm", deviceConfirmPage{
		pageData:    pageData{Title: "Approve device", User: &p.User, CSRFToken: p.CSRFToken},
		UserCode:    auth.FormatUserCode(d.UserCode),
		ClientName:  d.ClientName,
		RequestedAt: d.CreatedAt.UTC().Format("2 Jan 2006 15:04 MST"),
	})
}

// deviceDecision records the approve/deny decision.
func (h *Handlers) deviceDecision(c *gin.Context) {
	p := h.requireUser(c)
	if p == nil || !h.csrfOK(c, p) || !h.allowCodeAttempt(c, p) {
		return
	}
	decision := c.PostForm("decision")
	if decision != "approve" && decision != "deny" {
		h.message(c, http.StatusBadRequest, "Invalid request", "Choose Approve or Deny.", false)
		return
	}
	typed := c.PostForm("user_code")
	d, err := h.Devices.Decide(c.Request.Context(), p.User.ID, clientIP(c), typed, decision == "approve")
	if err != nil {
		h.deviceError(c, p, typed, err)
		return
	}
	if decision == "approve" {
		h.message(c, http.StatusOK, "Device approved",
			"\""+d.ClientName+"\" is now signed in as "+p.User.Email+". You can return to your terminal.", false)
		return
	}
	h.message(c, http.StatusOK, "Device denied", "The request was denied; the device was not signed in.", false)
}

func (h *Handlers) deviceError(c *gin.Context, p *auth.Principal, typed string, err error) {
	if e, ok := apperr.As(err); ok {
		h.render(c, http.StatusBadRequest, "device", devicePage{
			pageData: pageData{Title: "Connect a device", User: &p.User, CSRFToken: p.CSRFToken},
			UserCode: truncate(typed, 16),
			Error:    e.Message,
		})
		return
	}
	h.Logger.ErrorContext(c.Request.Context(), "device approval", "error", err.Error())
	h.message(c, http.StatusInternalServerError, "Something went wrong", "Please try again in a moment.", false)
}
