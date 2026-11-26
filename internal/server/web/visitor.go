package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/routes"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/visitor"
)

// The auth host (auth.<apps domain>) is served by the control plane behind
// the gateway: the gateway forwards its requests to /_visitor/... with the
// gateway secret in GatewayHeader. Requests without it are not found, so
// nobody can reach these pages around the gateway.

// VisitorPrefix is where the gateway forwards auth host requests.
const VisitorPrefix = "/_visitor"

// GatewayHeader carries the gateway secret on forwarded requests.
const GatewayHeader = "X-Nook-Gateway-Secret"

// visitorSessionCookie is the auth host's own session.
const visitorSessionCookie = "nook_visitor_auth"

// VisitorDeps are the auth host's collaborators.
type VisitorDeps struct {
	Visitors *visitor.Service
	// Provider is the OIDC provider with the auth host's redirect URL.
	Provider *identity.Provider
	Flows    *identity.Flows
	// GatewaySecret authenticates forwarded requests.
	GatewaySecret config.Secret
}

// RegisterVisitor mounts the auth host's pages.
func (h *Handlers) RegisterVisitor(r gin.IRouter, d *VisitorDeps) {
	v := &visitorPages{Handlers: h, VisitorDeps: *d}
	base := d.Visitors.Base()
	v.site = auth.Site{Origin: base.Origin(base.AuthHost()), Secure: base.Scheme == "https"}
	g := r.Group(VisitorPrefix, v.requireGateway)
	g.GET("/", v.home)
	g.GET("/start", v.start)
	g.GET("/callback", v.callback)
	g.GET("/sign-out", v.signOut)
	g.GET("/assets/nook.css", h.css)
}

type visitorPages struct {
	*Handlers
	VisitorDeps
	site auth.Site
}

type visitorPage struct {
	pageData
	Heading, Message, Email, Retry string
	SignOut                        bool
}

// requireGateway answers 404 unless the gateway forwarded the request.
func (v *visitorPages) requireGateway(c *gin.Context) {
	got := c.GetHeader(GatewayHeader)
	if subtle.ConstantTimeCompare([]byte(got), []byte(v.GatewaySecret.Reveal())) != 1 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Next()
}

func (v *visitorPages) page(c *gin.Context, status int, p *visitorPage) {
	p.Title = p.Heading
	c.Header("Cache-Control", "no-store")
	v.render(c, status, "visitor", p)
}

func (v *visitorPages) home(c *gin.Context) {
	p := &visitorPage{Heading: "Nook sign-in", Message: "This is where people sign in to the apps of this Nook installation."}
	if sess, err := v.authSession(c); err == nil {
		p.Email, p.SignOut = sess.Email, true
	}
	v.page(c, http.StatusOK, p)
}

func (v *visitorPages) authSession(c *gin.Context) (*sessionView, error) {
	token, ok := v.site.Cookie(c.Request, visitorSessionCookie)
	if !ok {
		return nil, visitor.ErrInvalid
	}
	s, err := v.Visitors.AuthSession(c.Request.Context(), token)
	if err != nil {
		return nil, err
	}
	return &sessionView{row: s, Email: s.Email}, nil
}

// start sends a visitor of an app host on: to the identity provider when
// not signed in here, back to the app with a code when allowed, or to a
// "no access" page.
func (v *visitorPages) start(c *gin.Context) {
	ctx := c.Request.Context()
	host := routes.StripPort(c.Query("app"))
	ret := auth.SafeReturnPath(c.Query("return"))
	app, err := v.Visitors.AppForHost(ctx, host)
	if errors.Is(err, visitor.ErrUnknownApp) {
		v.page(c, http.StatusNotFound, &visitorPage{Heading: "App not found", Message: "There is no app at this address."})
		return
	}
	if err != nil {
		v.failed(c, err)
		return
	}
	sess, err := v.authSession(c)
	if err != nil && !errors.Is(err, visitor.ErrInvalid) {
		v.failed(c, err)
		return
	}
	if sess == nil {
		v.beginSignIn(c, "/start?"+url.Values{"app": {host}, "return": {ret}}.Encode())
		return
	}
	allowed, err := v.Visitors.Allowed(ctx, &app, sess.Email)
	if err != nil {
		v.failed(c, err)
		return
	}
	if !allowed {
		v.page(c, http.StatusForbidden, &visitorPage{
			Heading: "No access", Email: sess.Email, SignOut: true,
			Message: "You are not allowed to open " + host + ". Ask the app's owners for access, or sign in with another account.",
		})
		return
	}
	code, err := v.Visitors.IssueCode(ctx, &app, host, &sess.row, ret)
	if err != nil {
		v.failed(c, err)
		return
	}
	base := v.Visitors.Base()
	c.Redirect(http.StatusFound, base.Origin(host)+"/_nook/callback?"+url.Values{"code": {code}}.Encode())
}

func (v *visitorPages) beginSignIn(c *gin.Context, returnTo string) {
	ctx := c.Request.Context()
	id, flow, err := v.Flows.Begin(ctx, returnTo)
	if err != nil {
		v.failed(c, err)
		return
	}
	target, err := v.Provider.AuthCodeURL(ctx, flow.State, flow.Nonce, flow.Verifier)
	if err != nil {
		v.Logger.WarnContext(ctx, "identity provider unavailable", "error", err.Error())
		v.page(c, http.StatusServiceUnavailable, &visitorPage{Heading: "Sign-in is unavailable",
			Message: "The identity provider cannot be reached right now. Please try again in a moment."})
		return
	}
	v.site.SetCookie(c.Writer, identity.FlowCookie, id, time.Now().Add(identity.FlowTTL))
	c.Redirect(http.StatusFound, target)
}

// callback completes the OIDC flow and gives the auth host a session.
func (v *visitorPages) callback(c *gin.Context) {
	ctx := c.Request.Context()
	flowID, _ := v.site.Cookie(c.Request, identity.FlowCookie)
	v.site.ClearCookie(c.Writer, identity.FlowCookie)
	if c.Query("error") != "" {
		v.page(c, http.StatusBadRequest, &visitorPage{Heading: "Sign-in was canceled", Message: "The identity provider did not complete the sign-in."})
		return
	}
	flow, err := v.Flows.Take(ctx, flowID)
	if err != nil {
		v.page(c, http.StatusBadRequest, &visitorPage{Heading: "Sign-in expired",
			Message: "This sign-in attempt has expired or was started in another browser. Open the app again to start over."})
		return
	}
	if subtle.ConstantTimeCompare([]byte(c.Query("state")), []byte(flow.State)) != 1 {
		v.Logger.WarnContext(ctx, "visitor sign-in rejected: state mismatch")
		v.page(c, http.StatusBadRequest, &visitorPage{Heading: "Sign-in failed", Message: "The sign-in response did not match the request."})
		return
	}
	code := c.Query("code")
	if code == "" || len(code) > 2048 {
		v.page(c, http.StatusBadRequest, &visitorPage{Heading: "Sign-in failed", Message: "The sign-in response was incomplete."})
		return
	}
	ident, err := v.Provider.Exchange(ctx, code, flow.Verifier, flow.Nonce)
	if err != nil {
		v.Logger.WarnContext(ctx, "visitor sign-in rejected: token exchange or verification failed", "error", err.Error())
		v.page(c, http.StatusBadRequest, &visitorPage{Heading: "Sign-in failed", Message: "The identity provider's response could not be verified."})
		return
	}
	sess, err := v.Visitors.SignIn(ctx, &ident, clientIP(c))
	if errors.Is(err, identity.ErrEmailNotVerified) {
		v.page(c, http.StatusForbidden, &visitorPage{Heading: "Email address not verified",
			Message: "Your identity provider has not verified your email address."})
		return
	}
	if err != nil {
		v.failed(c, err)
		return
	}
	v.site.SetCookie(c.Writer, visitorSessionCookie, sess.Token, sess.ExpiresAt)
	c.Redirect(http.StatusSeeOther, flow.ReturnTo)
}

// signOut ends the auth host's session (app hosts end theirs at
// /_nook/sign-out and send the visitor here).
func (v *visitorPages) signOut(c *gin.Context) {
	if token, ok := v.site.Cookie(c.Request, visitorSessionCookie); ok {
		if err := v.Visitors.SignOut(c.Request.Context(), token); err != nil {
			v.failed(c, err)
			return
		}
	}
	v.site.ClearCookie(c.Writer, visitorSessionCookie)
	v.page(c, http.StatusOK, &visitorPage{Heading: "Signed out", Message: "You are signed out of the apps of this Nook installation."})
}

func (v *visitorPages) failed(c *gin.Context, err error) {
	v.Logger.ErrorContext(c.Request.Context(), "visitor sign-in failed", "error", err.Error())
	v.page(c, http.StatusInternalServerError, &visitorPage{Heading: "Something went wrong", Message: "Please try again in a moment."})
}

// sessionView is a valid auth-host session.
type sessionView struct {
	row   store.VisitorSession
	Email string
}
