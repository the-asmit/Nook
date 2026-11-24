package auth

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Site describes the public origin of this Nook installation: the URL
// users type into their browser. Cookies and CSRF checks derive from it.
type Site struct {
	// Origin is scheme://host[:port], e.g. https://nook.example.com.
	Origin string
	// Secure is true for HTTPS origins.
	Secure bool
}

// NewSite derives the site from the public URL.
func NewSite(publicURL *url.URL) Site {
	return Site{
		Origin: publicURL.Scheme + "://" + publicURL.Host,
		Secure: publicURL.Scheme == "https",
	}
}

// CookieName returns the name to use for a cookie. Over HTTPS the
// __Host- prefix makes browsers enforce Secure, Path=/ and no Domain
// attribute, so a sibling subdomain (such as a user app) cannot set or
// overwrite it. Browsers reject __Host- cookies without Secure, so plain
// HTTP (allowed only for localhost development) uses the bare name.
func (s Site) CookieName(base string) string {
	if s.Secure {
		return "__Host-" + base
	}
	return base
}

// SetCookie sets an HttpOnly, SameSite=Lax, host-only cookie for the whole
// site. Lax still sends the cookie on top-level navigations (the redirect
// back from the identity provider) but not on cross-site subrequests or
// form posts.
func (s Site) SetCookie(w http.ResponseWriter, base, value string, expires time.Time) {
	//nolint:gosec // G124: Secure follows the site scheme; only localhost development is plain HTTP.
	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName(base),
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		Secure:   s.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie deletes a cookie set with SetCookie.
func (s Site) ClearCookie(w http.ResponseWriter, base string) {
	//nolint:gosec // G124: Secure follows the site scheme; only localhost development is plain HTTP.
	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName(base),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   s.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Cookie returns a cookie's value from the request.
func (s Site) Cookie(r *http.Request, base string) (string, bool) {
	c, err := r.Cookie(s.CookieName(base))
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// SameOrigin reports whether a request was initiated by a page of this
// site, using the Origin header or, if a browser omitted it, the Referer.
// Requests carrying neither are rejected: every modern browser sends at
// least one of them on state-changing requests.
func (s Site) SameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin == s.Origin
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return ref == s.Origin || strings.HasPrefix(ref, s.Origin+"/")
	}
	return false
}

// SafeReturnPath returns p if it is a local absolute path, otherwise "/".
// It prevents open redirects through return_to parameters: "//evil.com"
// and "/\evil.com" are protocol-relative URLs to browsers.
func SafeReturnPath(p string) string {
	if len(p) > 2048 || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, `/\`) {
		return "/"
	}
	u, err := url.Parse(p)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	return p
}
