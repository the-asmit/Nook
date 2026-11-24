package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/workspace"
)

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}

func clientIP(c *gin.Context) *netip.Addr {
	addr, err := netip.ParseAddr(c.ClientIP())
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	return &addr
}

type signinPage struct {
	pageData
	ProviderName string
	ReturnTo     string
}

func (h *Handlers) signinPage(c *gin.Context) {
	h.render(c, http.StatusOK, "signin", signinPage{
		pageData:     pageData{Title: "Sign in"},
		ProviderName: h.ProviderName,
		ReturnTo:     auth.SafeReturnPath(c.Query("return_to")),
	})
}

// login starts the authorization-code flow: it stores a new flow (state,
// nonce, PKCE verifier) server-side, binds it to this browser with a
// short-lived cookie and redirects to the identity provider.
func (h *Handlers) login(c *gin.Context) {
	id, flow, err := h.Flows.Begin(c.Request.Context(), c.Query("return_to"))
	if err != nil {
		h.Logger.ErrorContext(c.Request.Context(), "begin sign-in", "error", err.Error())
		h.message(c, http.StatusInternalServerError, "Sign-in is unavailable", "Please try again in a moment.", false)
		return
	}
	target, err := h.Provider.AuthCodeURL(c.Request.Context(), flow.State, flow.Nonce, flow.Verifier)
	if err != nil {
		h.Logger.WarnContext(c.Request.Context(), "identity provider unavailable", "error", err.Error())
		h.message(c, http.StatusServiceUnavailable, "Sign-in is unavailable",
			"Nook cannot reach its identity provider right now. Please try again in a moment.", false)
		return
	}
	h.Auth.Site().SetCookie(c.Writer, identity.FlowCookie, id, time.Now().Add(identity.FlowTTL))
	c.Redirect(http.StatusFound, target)
}

// callback completes the flow when the provider redirects back.
func (h *Handlers) callback(c *gin.Context) {
	ctx := c.Request.Context()
	site := h.Auth.Site()
	flowID, _ := site.Cookie(c.Request, identity.FlowCookie)
	site.ClearCookie(c.Writer, identity.FlowCookie)

	if errCode := c.Query("error"); errCode != "" {
		h.Logger.InfoContext(ctx, "identity provider returned an error", "oidc_error", truncate(errCode, 64))
		h.message(c, http.StatusBadRequest, "Sign-in was canceled",
			"The identity provider did not complete the sign-in. You can try again.", true)
		return
	}
	// Take consumes the flow, so a callback URL can be used at most once.
	flow, err := h.Flows.Take(ctx, flowID)
	if err != nil {
		if !errors.Is(err, identity.ErrFlowNotFound) {
			h.Logger.ErrorContext(ctx, "load sign-in flow", "error", err.Error())
		}
		h.message(c, http.StatusBadRequest, "Sign-in expired",
			"This sign-in attempt has expired or was started in another browser. Please start again.", true)
		return
	}
	// The state parameter must match the value we generated for *this*
	// browser's flow; otherwise someone is trying to inject their own
	// authorization code (login CSRF).
	if subtle.ConstantTimeCompare([]byte(c.Query("state")), []byte(flow.State)) != 1 {
		h.Logger.WarnContext(ctx, "sign-in rejected: state mismatch")
		h.message(c, http.StatusBadRequest, "Sign-in failed",
			"The sign-in response did not match the request. Please start again.", true)
		return
	}
	code := c.Query("code")
	if code == "" || len(code) > 2048 {
		h.message(c, http.StatusBadRequest, "Sign-in failed", "The sign-in response was incomplete. Please start again.", true)
		return
	}
	ident, err := h.Provider.Exchange(ctx, code, flow.Verifier, flow.Nonce)
	if err != nil {
		h.Logger.WarnContext(ctx, "sign-in rejected: token exchange or verification failed", "error", err.Error())
		h.message(c, http.StatusBadRequest, "Sign-in failed",
			"Nook could not verify the identity provider's response. Please start again.", true)
		return
	}

	previous, _ := site.Cookie(c.Request, auth.SessionCookie)
	res, err := h.SignIn.SignIn(ctx, &ident, identity.RequestMeta{
		UserAgent: c.Request.UserAgent(), IP: clientIP(c), PreviousSession: previous,
	})
	if err != nil {
		h.signInRefused(c, err)
		return
	}
	site.SetCookie(c.Writer, auth.SessionCookie, res.RawSession, res.Session.AbsoluteExpiresAt)
	c.Redirect(http.StatusSeeOther, flow.ReturnTo)
}

func (h *Handlers) signInRefused(c *gin.Context, err error) {
	switch {
	case errors.Is(err, identity.ErrNotInvited):
		h.message(c, http.StatusForbidden, "You have not been invited",
			"Your account is not allowed to use this Nook installation. Ask a workspace administrator to invite your email address, then sign in again.", false)
	case errors.Is(err, identity.ErrEmailNotVerified):
		h.message(c, http.StatusForbidden, "Email address not verified",
			"Your identity provider has not verified your email address. Verify it there, then sign in again.", false)
	case errors.Is(err, identity.ErrUserDisabled):
		h.message(c, http.StatusForbidden, "Account disabled", "Your Nook account has been disabled. Contact an administrator.", false)
	case errors.Is(err, identity.ErrEmailInUse):
		h.message(c, http.StatusConflict, "Account conflict",
			"Another Nook account already uses this email address. Contact an administrator.", false)
	default:
		h.Logger.ErrorContext(c.Request.Context(), "sign-in failed", "error", err.Error())
		h.message(c, http.StatusInternalServerError, "Sign-in failed", "Something went wrong. Please try again in a moment.", false)
	}
}

func (h *Handlers) logout(c *gin.Context) {
	p, err := h.currentUser(c)
	if err != nil {
		h.Logger.ErrorContext(c.Request.Context(), "authenticate browser", "error", err.Error())
		h.message(c, http.StatusInternalServerError, "Something went wrong", "Please try again in a moment.", false)
		return
	}
	if p == nil {
		c.Redirect(http.StatusSeeOther, "/signed-out")
		return
	}
	if !h.csrfOK(c, p) {
		return
	}
	if err := auth.Logout(c.Request.Context(), h.Store, p, clientIP(c)); err != nil {
		h.Logger.ErrorContext(c.Request.Context(), "sign out", "error", err.Error())
		h.message(c, http.StatusInternalServerError, "Sign-out failed", "Please try again in a moment.", false)
		return
	}
	h.Auth.Site().ClearCookie(c.Writer, auth.SessionCookie)
	c.Redirect(http.StatusSeeOther, "/signed-out")
}

func (h *Handlers) signedOut(c *gin.Context) {
	h.message(c, http.StatusOK, "Signed out", "You have been signed out of Nook.", true)
}

// csrfOK checks a form submission and renders the failure page itself.
func (h *Handlers) csrfOK(c *gin.Context, p *auth.Principal) bool {
	if err := h.Auth.CheckCSRF(c.Request, p, c.PostForm(auth.FormCSRFToken)); err != nil {
		h.Logger.WarnContext(c.Request.Context(), "form rejected: CSRF check failed", "error", err.Error())
		h.message(c, http.StatusForbidden, "Request blocked",
			"This form submission could not be verified. Go back, reload the page and try again.", false)
		return false
	}
	return true
}

type homePage struct {
	pageData
	Workspaces []workspace.View
	PublicURL  string
}

func (h *Handlers) home(c *gin.Context) {
	p := h.requireUser(c)
	if p == nil {
		return
	}
	views, err := h.Workspaces.List(c.Request.Context(), workspace.Actor{UserID: p.User.ID}, "", 50)
	if err != nil {
		h.Logger.ErrorContext(c.Request.Context(), "list workspaces", "error", err.Error())
		h.message(c, http.StatusInternalServerError, "Something went wrong", "Please try again in a moment.", false)
		return
	}
	h.render(c, http.StatusOK, "home", homePage{
		pageData:   pageData{Title: "Home", User: &p.User, CSRFToken: p.CSRFToken},
		Workspaces: views,
		PublicURL:  h.PublicURL,
	})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
