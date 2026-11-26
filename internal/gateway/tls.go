package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/routes"
)

// errUnknownHost is the host policy's refusal.
var errUnknownHost = errors.New("not a host of this Nook installation")

// tls returns the HTTPS configuration and the plain-HTTP handler (ACME
// HTTP-01 challenges, then a redirect to HTTPS) for acme and files modes.
func (g *Gateway) tls(cp *controlPlane) (*tls.Config, http.Handler, error) {
	redirect := http.HandlerFunc(g.handler.redirectToHTTPS)
	switch g.cfg.TLSMode {
	case TLSFiles:
		cert, err := tls.LoadX509KeyPair(g.cfg.TLSCertPath, g.cfg.TLSKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load the gateway certificate: %w", err)
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, redirect, nil
	case TLSACME:
		m := g.acmeManager(cp)
		cfg := m.TLSConfig()
		cfg.MinVersion = tls.VersionTLS12
		return cfg, m.HTTPHandler(redirect), nil
	default:
		return nil, nil, fmt.Errorf("TLS mode %s has no TLS listener", g.cfg.TLSMode)
	}
}

// redirectToHTTPS sends plain-HTTP requests for Nook's hosts to HTTPS.
// The target host comes from the route table, never from the request, so
// the gateway cannot be made to redirect anywhere else.
func (h *handler) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSuffix(routes.StripPort(r.Host), "."))
	if host != h.authHost {
		route, ok := h.table.lookup(host)
		if !ok {
			page(w, r, http.StatusNotFound, "App not found", "There is no app at this address.", nil)
			return
		}
		host = route.Host
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		page(w, r, http.StatusBadRequest, "HTTPS required", "Use https:// for this address.", nil)
		return
	}
	// G710: the host comes from the route table and the path is a
	// same-origin path, so the target is always one of Nook's hosts.
	http.Redirect(w, r, h.base.Origin(host)+auth.SafeReturnPath(r.URL.RequestURI()), http.StatusPermanentRedirect) //nolint:gosec // G710: see above.
}

// acmeManager obtains certificates on demand (TLS-ALPN-01 on the HTTPS
// listener, HTTP-01 on the HTTP one) and stores them through the control
// plane, so every gateway instance shares them.
func (g *Gateway) acmeManager(cp *controlPlane) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      g.cfg.ACMEEmail,
		Cache:      certCache{cp: cp},
		HostPolicy: hostPolicy(g.handler.authHost, g.table, cp.knownHost),
		Client:     &acme.Client{DirectoryURL: g.cfg.ACMEDirectoryURL},
	}
}

// hostPolicy is the "ask" check: a certificate is requested only for the
// auth host and hosts of existing apps, so a client cannot make Nook ask
// the CA for arbitrary names (and burn its rate limits).
func hostPolicy(authHost string, tbl *table, knownHost func(context.Context, string) (bool, error)) autocert.HostPolicy {
	return func(ctx context.Context, host string) error {
		host = strings.ToLower(host)
		if host == authHost {
			return nil
		}
		if _, ok := tbl.lookup(host); ok {
			return nil
		}
		// The table may lag behind a brand-new app; the control plane is
		// authoritative.
		known, err := knownHost(ctx, host)
		if err != nil {
			return fmt.Errorf("check host: %w", err)
		}
		if !known {
			return errUnknownHost
		}
		return nil
	}
}

// certCache stores autocert's certificates and account key through the
// control plane, which seals them with its secrets keyring.
type certCache struct {
	cp *controlPlane
}

func (c certCache) Get(ctx context.Context, name string) ([]byte, error) {
	data, err := c.cp.getCert(ctx, name)
	if errors.Is(err, errNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	return data, err
}

func (c certCache) Put(ctx context.Context, name string, data []byte) error {
	return c.cp.putCert(ctx, name, data)
}

func (c certCache) Delete(ctx context.Context, name string) error {
	return c.cp.deleteCert(ctx, name)
}
