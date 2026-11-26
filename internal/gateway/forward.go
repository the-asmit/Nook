package gateway

import (
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"unicode"

	"github.com/the-asmit/nook/internal/routes"
)

// rewriteApp builds the request to the app's instance.
func (h *handler) rewriteApp(pr *httputil.ProxyRequest) {
	route, _ := pr.In.Context().Value(ctxRoute{}).(routes.Route)
	pr.SetURL(&url.URL{Scheme: "http", Host: route.Upstream})
	pr.Out.Host = pr.In.Host
	h.forwardHeaders(pr)
	stripNookCookies(pr.Out.Header)
	if who, ok := pr.In.Context().Value(ctxIdentity{}).(identity); ok {
		pr.Out.Header.Set(HeaderEmail, who.Email)
		if who.Name != "" {
			pr.Out.Header.Set(HeaderName, headerSafe(who.Name))
		}
	}
}

// forwardHeaders removes X-Nook-* headers a client may have sent and sets
// X-Forwarded-For, -Proto, -Host and the request ID.
func (h *handler) forwardHeaders(pr *httputil.ProxyRequest) {
	for name := range pr.Out.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-nook-") {
			pr.Out.Header.Del(name)
		}
	}
	pr.Out.Header.Set("X-Forwarded-For", h.forwardedFor(pr.In))
	pr.Out.Header.Set("X-Forwarded-Proto", h.base.Scheme)
	pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
	pr.Out.Header.Set(headerRequestID, requestID(pr.In.Context()))
}

// nookCookie reports whether a cookie is one of Nook's (never forwarded:
// the app must not see visitor sessions).
func nookCookie(name string) bool {
	return strings.HasPrefix(name, "nook_") || strings.HasPrefix(name, "__Host-nook_")
}

// stripNookCookies removes Nook's cookies from the Cookie header, keeping
// the app's own cookies exactly as sent.
func stripNookCookies(hdr http.Header) {
	values := hdr.Values("Cookie")
	if len(values) == 0 {
		return
	}
	var kept []string
	for _, v := range values {
		for part := range strings.SplitSeq(v, ";") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			name, _, _ := strings.Cut(p, "=")
			if !nookCookie(strings.TrimSpace(name)) {
				kept = append(kept, p)
			}
		}
	}
	hdr.Del("Cookie")
	if len(kept) > 0 {
		hdr.Set("Cookie", strings.Join(kept, "; "))
	}
}

// headerSafe keeps printable characters of a display name.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, truncate(s, 200))
}

// remoteIP is the peer address of the connection.
func remoteIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (h *handler) trustedAddr(a netip.Addr) bool {
	for _, p := range h.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (h *handler) fromTrustedProxy(r *http.Request) bool { return h.trustedAddr(remoteIP(r)) }

// clientIP is the visitor's address: the connection's peer, or, behind
// trusted proxies, the last address in X-Forwarded-For that is not one of
// them.
func (h *handler) clientIP(r *http.Request) string {
	peer := remoteIP(r)
	if !h.trustedAddr(peer) {
		return peer.String()
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !h.trustedAddr(a.Unmap()) {
			return a.Unmap().String()
		}
	}
	return peer.String()
}

// forwardedFor is X-Forwarded-For for the upstream: the chain from trusted
// proxies, otherwise only the peer (a client's own header is dropped).
func (h *handler) forwardedFor(r *http.Request) string {
	peer := remoteIP(r).String()
	if h.fromTrustedProxy(r) {
		if prior := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); prior != "" {
			return prior + ", " + peer
		}
	}
	return peer
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
