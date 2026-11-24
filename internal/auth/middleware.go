package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/platform/httpserver"
)

// SessionCookie is the base name of the session cookie (see Site.CookieName).
const SessionCookie = "nook_session"

// HeaderCSRFToken carries the CSRF token on API requests made by a
// signed-in browser.
const HeaderCSRFToken = "X-CSRF-Token" //nolint:gosec // G101: a header name, not a credential.

// FormCSRFToken carries the CSRF token in server-rendered HTML forms.
const FormCSRFToken = "csrf_token"

// Authenticator turns request credentials into a Principal.
type Authenticator struct {
	sessions *Sessions
	tokens   *APITokens
	site     Site
	logger   *slog.Logger
}

// NewAuthenticator returns an authenticator.
func NewAuthenticator(sessions *Sessions, tokens *APITokens, site Site, logger *slog.Logger) *Authenticator {
	return &Authenticator{sessions: sessions, tokens: tokens, site: site, logger: logger}
}

// Site returns the site the authenticator was configured for.
func (a *Authenticator) Site() Site {
	return a.site
}

// Authenticate returns the request's principal: from an
// "Authorization: Bearer" API token if that header is present, otherwise
// from the session cookie. It returns (nil, nil) when the request carries
// no credentials and ErrInvalidCredentials when they are not valid.
func (a *Authenticator) Authenticate(r *http.Request) (*Principal, error) {
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, token, ok := strings.Cut(h, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return nil, ErrInvalidCredentials
		}
		return a.tokens.Authenticate(r.Context(), strings.TrimSpace(token))
	}
	raw, ok := a.site.Cookie(r, SessionCookie)
	if !ok {
		return nil, nil
	}
	return a.sessions.Authenticate(r.Context(), raw)
}

// CheckCSRF verifies a state-changing request authenticated by cookie: it
// must come from a page of this site and echo the session's CSRF token.
// Requests authenticated with a bearer token are exempt, because browsers
// never attach Authorization headers on their own.
func (a *Authenticator) CheckCSRF(r *http.Request, p *Principal, presented string) error {
	if p.Method != MethodSession || isSafeMethod(r.Method) {
		return nil
	}
	if !a.site.SameOrigin(r) {
		return errors.New("request did not originate from this site")
	}
	if !ValidCSRFToken(p, presented) {
		return errors.New("missing or invalid CSRF token")
	}
	return nil
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// RequireAPI is Gin middleware for JSON API routes: it rejects requests
// without valid credentials (401) and cookie-authenticated state changes
// that fail the CSRF check (403), then stores the principal in the
// request context.
func (a *Authenticator) RequireAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		p, err := a.Authenticate(c.Request)
		switch {
		case errors.Is(err, ErrInvalidCredentials) || (err == nil && p == nil):
			c.Header("WWW-Authenticate", `Bearer realm="nook"`)
			httpserver.AbortWithError(c, http.StatusUnauthorized, "unauthenticated",
				"sign in or provide a valid API token")
			return
		case err != nil:
			a.logger.ErrorContext(c.Request.Context(), "authentication failed", "error", err.Error())
			httpserver.AbortWithError(c, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		if err := a.CheckCSRF(c.Request, p, c.GetHeader(HeaderCSRFToken)); err != nil {
			httpserver.AbortWithError(c, http.StatusForbidden, "csrf_failed", fmt.Sprintf("CSRF check failed: %v", err))
			return
		}
		c.Request = c.Request.WithContext(WithPrincipal(c.Request.Context(), p))
		c.Next()
	}
}
