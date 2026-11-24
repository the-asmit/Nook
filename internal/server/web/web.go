// Package web serves Nook's few server-rendered HTML pages: sign-in,
// sign-out, "not invited" and device approval. They use html/template,
// whose contextual auto-escaping prevents injection, under a strict
// Content-Security-Policy that allows no scripts at all. The React
// dashboard of a later stage talks to the JSON API instead.
package web

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/device"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/ratelimit"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets/nook.css
var stylesheet []byte

// pageCSP allows only our own stylesheet, HTTPS avatar images and forms
// posting back to us; no scripts, frames, plugins or base-URI tricks.
const pageCSP = "default-src 'none'; style-src 'self'; img-src 'self' https:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// Deps are the collaborators of the web handlers.
type Deps struct {
	Logger     *slog.Logger
	Store      *store.Store
	Auth       *auth.Authenticator
	Flows      *identity.Flows
	Provider   *identity.Provider
	SignIn     *identity.Service
	Devices    *device.Service
	Workspaces *workspace.Service
	Limiter    *ratelimit.Limiter
	// ProviderName labels the sign-in button.
	ProviderName string
	// PublicURL is shown in instructions (e.g. for `nook login`).
	PublicURL string
}

// Handlers serves the HTML pages.
type Handlers struct {
	Deps
	pages map[string]*template.Template
}

// New parses the templates; a template error is a build defect and fails
// startup.
func New(d *Deps) (*Handlers, error) {
	pages := map[string]*template.Template{}
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	for _, name := range names {
		if name == "templates/layout.html" {
			continue
		}
		t, err := template.ParseFS(templateFS, "templates/layout.html", name)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		pages[name[len("templates/"):len(name)-len(".html")]] = t
	}
	return &Handlers{Deps: *d, pages: pages}, nil
}

// Register mounts the HTML routes.
func (h *Handlers) Register(r gin.IRouter) {
	r.GET("/", h.home)
	r.GET("/signin", h.signinPage)
	r.GET("/auth/login", h.login)
	r.GET(identity.CallbackPath, h.callback)
	r.POST("/auth/logout", h.logout)
	r.GET("/signed-out", h.signedOut)
	r.GET("/device", h.devicePage)
	r.POST("/device", h.deviceLookup)
	r.POST("/device/decision", h.deviceDecision)
	r.GET("/assets/nook.css", h.css)
}

// pageData is common to every page.
type pageData struct {
	Title     string
	User      *store.User
	CSRFToken string
}

// render executes a page template into a buffer first, so a template error
// produces a clean 500 instead of a half-written page.
func (h *Handlers) render(c *gin.Context, status int, page string, data any) {
	t, ok := h.pages[page]
	if !ok {
		h.Logger.ErrorContext(c.Request.Context(), "unknown page template", "page", page)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.Logger.ErrorContext(c.Request.Context(), "render page", "page", page, "error", err.Error())
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Header("Content-Security-Policy", pageCSP)
	c.Data(status, "text/html; charset=utf-8", buf.Bytes())
}

// messagePage is the data for the generic message template.
type messagePage struct {
	pageData
	Heading    string
	Message    string
	ShowSignIn bool
	ShowHome   bool
}

func (h *Handlers) message(c *gin.Context, status int, heading, msg string, showSignIn bool) {
	h.render(c, status, "message", messagePage{
		pageData: pageData{Title: heading}, Heading: heading, Message: msg, ShowSignIn: showSignIn, ShowHome: !showSignIn,
	})
}

func (h *Handlers) css(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "text/css; charset=utf-8", stylesheet)
}

// currentUser authenticates the browser by session cookie only; API
// tokens are not accepted on HTML pages.
func (h *Handlers) currentUser(c *gin.Context) (*auth.Principal, error) {
	raw, ok := h.Auth.Site().Cookie(c.Request, auth.SessionCookie)
	if !ok {
		return nil, nil
	}
	if !auth.LooksLikeSecret(raw) {
		return nil, nil
	}
	p, err := h.Auth.Authenticate(withoutAuthorization(c.Request))
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return nil, nil
	}
	return p, err
}

// withoutAuthorization strips any Authorization header so the cookie is
// the only credential considered.
func withoutAuthorization(r *http.Request) *http.Request {
	if r.Header.Get("Authorization") == "" {
		return r
	}
	r2 := r.Clone(r.Context())
	r2.Header.Del("Authorization")
	return r2
}

// requireUser returns the signed-in user, or redirects to the sign-in page
// (coming back to the current URL afterwards) and returns nil.
func (h *Handlers) requireUser(c *gin.Context) *auth.Principal {
	p, err := h.currentUser(c)
	if err != nil {
		h.Logger.ErrorContext(c.Request.Context(), "authenticate browser", "error", err.Error())
		h.message(c, http.StatusInternalServerError, "Something went wrong", "Please try again in a moment.", false)
		return nil
	}
	if p == nil {
		c.Redirect(http.StatusSeeOther, "/signin?return_to="+urlQueryEscape(c.Request.URL.RequestURI()))
		return nil
	}
	return p
}
