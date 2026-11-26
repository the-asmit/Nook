package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/routes"
)

// Visitor identity headers set for the app (any incoming X-Nook-* header
// is removed first, so the app can trust them).
const (
	HeaderEmail = "X-Nook-Email"
	HeaderName  = "X-Nook-Name"
)

// gatewaySecretHeader authenticates requests forwarded to the auth host
// pages of the control plane (web.GatewayHeader).
const gatewaySecretHeader = "X-Nook-Gateway-Secret" //nolint:gosec // G101: a header name, not a credential.

// sessionCookie is the visitor's session on one app host.
const sessionCookie = "nook_visitor"

// headerRequestID is the request ID header.
const headerRequestID = "X-Request-ID"

type ctxKey int

const requestIDKey ctxKey = 0

// requestID returns the request's ID.
func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// handler serves app hosts and the auth host.
type handler struct {
	cfg      *Config
	base     routes.Base
	authHost string
	table    *table
	cp       *controlPlane
	cache    *accessCache
	ipLimit  *limiter
	appLimit *limiter
	trusted  []netip.Prefix
	appProxy *httputil.ReverseProxy
	cpProxy  *httputil.ReverseProxy
	conns    *connTracker
	m        *metrics
	logger   *slog.Logger
	// waker holds requests for sleeping apps until they wake.
	waker *waker
	// touch records a request for an app (activity, for sleeping idle
	// apps); a no-op until the gateway sets its recorder.
	touch func(app uuid.UUID)
}

type ctxRoute struct{}
type ctxIdentity struct{}

type identity struct {
	Email, Name string
}

func newHandler(cfg *Config, tbl *table, cp *controlPlane, m *metrics, conns *connTracker, logger *slog.Logger) (*handler, error) {
	trusted, err := cfg.trustedProxies()
	if err != nil {
		return nil, err
	}
	cpURL, err := url.Parse(cfg.ControlPlaneURL)
	if err != nil {
		return nil, err
	}
	base := cfg.base()
	h := &handler{
		cfg: cfg, base: base, authHost: base.AuthHost(), table: tbl, cp: cp, cache: newAccessCache(cfg.AccessCacheTTL),
		ipLimit: newLimiter(cfg.RatePerIP, cfg.BurstPerIP), appLimit: newLimiter(cfg.RatePerApp, cfg.BurstPerApp),
		trusted: trusted, conns: conns, m: m, logger: logger, touch: func(uuid.UUID) {},
	}
	h.waker = newWaker(cp.wake, tbl, cfg.WakeTimeout, cfg.WakeMaxHeld, m)
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: cfg.UpstreamHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
	h.appProxy = &httputil.ReverseProxy{
		Rewrite:       h.rewriteApp,
		Transport:     transport,
		FlushInterval: -1, // stream responses (SSE) as they come
		ErrorHandler:  h.upstreamError,
	}
	h.cpProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cpURL)
			pr.Out.URL.Path = "/_visitor" + pr.In.URL.Path
			pr.Out.URL.RawPath = ""
			h.forwardHeaders(pr)
			pr.Out.Header.Set(gatewaySecretHeader, cfg.Secret.Reveal())
		},
		Transport:    &http.Transport{ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 90 * time.Second},
		ErrorHandler: h.upstreamError,
	}
	return h, nil
}

// statusWriter records the status and size and tracks hijacked
// (upgraded) connections for draining.
type statusWriter struct {
	http.ResponseWriter
	h        *handler
	status   int
	bytes    int64
	upgraded bool
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Hijack hands over the connection (WebSocket upgrades) and tracks it.
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.upgraded = true
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return w.h.conns.track(conn, w.h.m), rw, nil
}

// Unwrap gives http.ResponseController access to the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ServeHTTP routes a request by host.
func (h *handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := r.Header.Get(headerRequestID)
	if !h.fromTrustedProxy(r) || !validRequestID(id) {
		id = rand.Text()
	}
	r = r.WithContext(context.WithValue(r.Context(), requestIDKey, id))
	w := &statusWriter{ResponseWriter: rw, h: h}
	w.Header().Set(headerRequestID, id)
	host := strings.ToLower(strings.TrimSuffix(routes.StripPort(r.Host), "."))
	label := "-"
	defer func() { //nolint:contextcheck // logs on the request's own context.
		status := w.status
		if status == 0 {
			status = http.StatusOK
		}
		h.m.requests.WithLabelValues(label, strconv.Itoa(status)).Inc()
		h.m.duration.WithLabelValues(label).Observe(time.Since(start).Seconds())
		// Path only: query strings may carry codes and tokens; cookies
		// and Authorization headers are never logged.
		h.logger.InfoContext(r.Context(), "request", "request_id", id, "host", host, "method", r.Method,
			"path", truncate(r.URL.Path, 256), "status", status, "bytes", w.bytes, "app", label,
			"client_ip", h.clientIP(r), "duration_ms", time.Since(start).Milliseconds(), "upgraded", w.upgraded)
	}()
	if !h.ipLimit.allow(h.clientIP(r)) {
		h.m.limited.WithLabelValues("ip").Inc()
		w.Header().Set("Retry-After", "1")
		page(w, r, http.StatusTooManyRequests, "Too many requests", "Slow down and try again in a moment.", nil)
		return
	}
	if host == h.authHost {
		label = "auth"
		h.cpProxy.ServeHTTP(w, r)
		return
	}
	route, ok := h.table.lookup(host)
	if !ok {
		page(w, r, http.StatusNotFound, "App not found", "There is no app at this address.", nil)
		return
	}
	label = route.Workspace + "/" + route.App
	h.touch(route.AppID)
	if !h.appLimit.allow(route.AppID.String()) {
		h.m.limited.WithLabelValues("app").Inc()
		w.Header().Set("Retry-After", "1")
		page(w, r, http.StatusTooManyRequests, "Too many requests", "This app is receiving too many requests. Try again in a moment.", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxBodyBytes)
	if strings.HasPrefix(r.URL.Path, "/_nook/") || r.URL.Path == "/_nook" {
		h.serveReserved(w, r, &route)
		return
	}
	var who *identity
	if route.Access != routes.AccessPublic {
		var stop bool
		who, stop = h.authenticate(w, r, &route)
		if stop {
			return
		}
	}
	if routes.Wakeable(route.State) {
		// Only visitors allowed in (above) wake an app.
		woken, err := h.waker.hold(r.Context(), &route)
		switch {
		case errors.Is(err, context.Canceled):
			return // the visitor went away
		case errors.Is(err, routes.ErrNotFound):
			page(w, r, http.StatusNotFound, "App not found", "There is no app at this address.", nil)
			return
		case err != nil:
			w.Header().Set("Retry-After", wakeRetryAfter)
			page(w, r, http.StatusServiceUnavailable, "App waking up", "This app was asleep and is starting. Try again in a few seconds.", nil)
			return
		}
		route = woken
	}
	if !route.Serving() {
		page(w, r, http.StatusServiceUnavailable, "App unavailable", routes.Describe(route.State), nil)
		return
	}
	ctx := context.WithValue(r.Context(), ctxRoute{}, route)
	if who != nil {
		ctx = context.WithValue(ctx, ctxIdentity{}, *who)
	}
	h.appProxy.ServeHTTP(w, r.WithContext(ctx))
}

// site is the cookie site of an app host.
func (h *handler) site(host string) auth.Site {
	return auth.Site{Origin: h.base.Origin(host), Secure: h.base.Scheme == "https"}
}

// authenticate finds the visitor's session and its access decision. It
// writes a response (redirect to the auth host, denial) and returns
// stop=true when the request must not be proxied.
func (h *handler) authenticate(w http.ResponseWriter, r *http.Request, route *routes.Route) (*identity, bool) {
	token, ok := h.site(route.Host).Cookie(r, sessionCookie)
	if ok {
		res, cached, err := h.cache.get(r.Context(), token, route.Host, h.cp.check)
		if err != nil {
			h.logger.WarnContext(r.Context(), "visitor session check failed", "error", err.Error())
			page(w, r, http.StatusServiceUnavailable, "Sign-in unavailable", "Access to this app cannot be checked right now. Try again in a moment.", nil)
			return nil, true
		}
		h.m.authCheck.WithLabelValues(res.Status, strconv.FormatBool(cached)).Inc()
		switch res.Status {
		case "ok":
			return &identity{Email: res.Email, Name: res.Name}, false
		case "denied":
			page(w, r, http.StatusForbidden, "No access", "You ("+res.Email+") are not allowed to open this app. Ask its owners for access.",
				&pageLink{URL: "/_nook/sign-out", Text: "Sign in with another account"})
			return nil, true
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		page(w, r, http.StatusUnauthorized, "Sign-in required", "Sign in to use this app.", &pageLink{URL: "/", Text: "Open the app"})
		return nil, true
	}
	target := h.base.Origin(h.authHost) + "/start?" + url.Values{
		"app": {route.Host}, "return": {auth.SafeReturnPath(r.URL.RequestURI())},
	}.Encode()
	http.Redirect(w, r, target, http.StatusFound)
	return nil, true
}

// serveReserved handles /_nook/* on app hosts: the sign-in callback and
// sign-out. Nothing under /_nook/ reaches an app.
func (h *handler) serveReserved(w http.ResponseWriter, r *http.Request, route *routes.Route) {
	site := h.site(route.Host)
	switch r.URL.Path {
	case "/_nook/callback":
		if r.Method != http.MethodGet {
			page(w, r, http.StatusMethodNotAllowed, "Not allowed", "Use the link from the sign-in page.", nil)
			return
		}
		res, err := h.cp.exchange(r.Context(), r.URL.Query().Get("code"), route.Host)
		if errors.Is(err, errInvalidCode) {
			page(w, r, http.StatusBadRequest, "Sign-in link expired", "This sign-in link has expired or was already used.",
				&pageLink{URL: "/", Text: "Open the app again"})
			return
		}
		if err != nil {
			h.logger.WarnContext(r.Context(), "visitor code exchange failed", "error", err.Error())
			page(w, r, http.StatusServiceUnavailable, "Sign-in unavailable", "Try again in a moment.", nil)
			return
		}
		site.SetCookie(w, sessionCookie, res.Token, res.ExpiresAt)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, auth.SafeReturnPath(res.ReturnPath), http.StatusSeeOther)
	case "/_nook/sign-out":
		if token, ok := site.Cookie(r, sessionCookie); ok {
			if err := h.cp.signOut(r.Context(), token); err != nil {
				h.logger.WarnContext(r.Context(), "visitor sign-out failed", "error", err.Error())
			}
			h.cache.forget(token, route.Host)
		}
		site.ClearCookie(w, sessionCookie)
		http.Redirect(w, r, h.base.Origin(h.authHost)+"/sign-out", http.StatusSeeOther)
	default:
		page(w, r, http.StatusNotFound, "Not found", "This address is reserved by Nook.", nil)
	}
}

func (h *handler) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return // the visitor went away
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		page(w, r, http.StatusRequestEntityTooLarge, "Request too large", "The request body is larger than this gateway accepts.", nil)
		return
	}
	h.logger.WarnContext(r.Context(), "upstream unreachable", "error", err.Error())
	page(w, r, http.StatusBadGateway, "App unreachable", "The app did not answer. Try again in a moment.", nil)
}
