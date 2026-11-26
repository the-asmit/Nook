// Package visitor is the control plane's side of app visitors: the routes
// the gateways serve, the auth host's sign-in (OIDC, with a session of its
// own), the short-lived single-use codes that carry a sign-in to one app
// host, the per-app-host sessions the gateways check (re-deciding access
// on every check), and the certificates the gateways obtain.
//
// Visitors need no Nook account: access is decided by the verified email
// of their ID token. Sessions and codes are stored only as SHA-256 hashes
// and are bound to the host they were issued for.
package visitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/routes"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
)

// Config holds visitor session lifetimes.
type Config struct {
	// SessionIdle ends a session unused for this long.
	SessionIdle time.Duration `env:"NOOK_VISITOR_SESSION_IDLE_TIMEOUT" envDefault:"12h"`
	// SessionAbsolute ends every session after this long.
	SessionAbsolute time.Duration `env:"NOOK_VISITOR_SESSION_ABSOLUTE_TIMEOUT" envDefault:"168h"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	return errors.Join(
		config.CheckDuration("NOOK_VISITOR_SESSION_IDLE_TIMEOUT", c.SessionIdle, time.Minute, 30*24*time.Hour),
		config.CheckDuration("NOOK_VISITOR_SESSION_ABSOLUTE_TIMEOUT", c.SessionAbsolute, c.SessionIdle, 90*24*time.Hour),
	)
}

// codeTTL is how long an auth-host code may wait for its app host.
const codeTTL = time.Minute

// Errors.
var (
	// ErrInvalid means a code, session or host is unknown, expired, used
	// or bound to another host.
	ErrInvalid = errors.New("invalid or expired")
	// ErrUnknownApp means a host names no live app.
	ErrUnknownApp = errors.New("no such app")
)

// Service implements visitor sign-in for the gateways.
type Service struct {
	store       *store.Store
	keyring     *secrets.Keyring
	base        routes.Base
	allowPublic bool
	cfg         Config
	now         func() time.Time
}

// New returns the service.
func New(st *store.Store, keyring *secrets.Keyring, base routes.Base, allowPublic bool, cfg *Config) *Service {
	return &Service{store: st, keyring: keyring, base: base, allowPublic: allowPublic, cfg: *cfg, now: time.Now}
}

// Base is the apps domain.
func (s *Service) Base() routes.Base { return s.base }

// routeFrom builds a route from a store row (GetRouteRow converts to it:
// both queries select the same columns).
func (s *Service) routeFrom(r *store.ListRoutesRow) routes.Route {
	out := routes.Route{
		AppID: r.AppID, Host: s.base.Host(r.WorkspaceSlug, r.AppSlug), Workspace: r.WorkspaceSlug, App: r.AppSlug,
		Access: routes.Effective(string(r.AccessMode), s.allowPublic),
		State:  routes.StateOf(string(r.DesiredState), r.CurrentDeploymentID != nil, r.InstanceState, r.Sleeping, r.Waking),
	}
	if r.Address != "" && r.HostPort != nil && (r.InstanceState == "healthy" || r.InstanceState == "unhealthy" || r.InstanceState == "starting") {
		out.Upstream = net.JoinHostPort(r.Address, strconv.Itoa(int(*r.HostPort)))
	}
	return out
}

// Routes returns every app's route.
func (s *Service) Routes(ctx context.Context) ([]routes.Route, error) {
	rows, err := s.store.ListRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	out := make([]routes.Route, 0, len(rows))
	for i := range rows {
		out = append(out, s.routeFrom(&rows[i]))
	}
	return out, nil
}

// Route returns one app's route.
func (s *Service) Route(ctx context.Context, appID uuid.UUID) (routes.Route, error) {
	r, err := s.store.GetRoute(ctx, appID)
	if store.IsNotFound(err) {
		return routes.Route{}, routes.ErrNotFound
	}
	if err != nil {
		return routes.Route{}, fmt.Errorf("read route: %w", err)
	}
	row := store.ListRoutesRow(r)
	return s.routeFrom(&row), nil
}

// KnownHost reports whether a certificate may be requested for host: an
// existing app's host or the auth host. It keeps anyone from making Nook
// ask the CA for certificates for arbitrary names.
func (s *Service) KnownHost(ctx context.Context, host string) (bool, error) {
	if host == s.base.AuthHost() {
		return true, nil
	}
	_, err := s.AppForHost(ctx, host)
	if errors.Is(err, ErrUnknownApp) {
		return false, nil
	}
	return err == nil, err
}

// AppForHost returns the live app an app host name denotes.
func (s *Service) AppForHost(ctx context.Context, host string) (store.App, error) {
	ws, app, ok := s.base.Parse(host)
	if !ok {
		return store.App{}, ErrUnknownApp
	}
	a, err := s.store.GetAppBySlugs(ctx, store.GetAppBySlugsParams{WorkspaceSlug: ws, AppSlug: app})
	if store.IsNotFound(err) {
		return store.App{}, ErrUnknownApp
	}
	if err != nil {
		return store.App{}, fmt.Errorf("look up app: %w", err)
	}
	return a, nil
}

// Allowed decides access for a verified email (see apps.Decide).
func (s *Service) Allowed(ctx context.Context, app *store.App, email string) (bool, error) {
	return apps.Decide(ctx, s.store.Queries, app, email, s.allowPublic)
}

// Session is a visitor session as the caller sees it.
type Session struct {
	Token     string
	ExpiresAt time.Time
	Email     string
	Name      string
}

func (s *Service) newSession(ctx context.Context, q *store.Queries, host string, appID *uuid.UUID, email, name, issuer, subject string) (Session, error) {
	token := auth.NewSecret()
	now := s.now()
	row, err := q.CreateVisitorSession(ctx, store.CreateVisitorSessionParams{
		TokenHash: auth.Hash(token), Host: host, AppID: appID, Email: email, Name: truncate(name, 200),
		Issuer: issuer, Subject: subject, IdleExpiresAt: now.Add(s.cfg.SessionIdle), AbsoluteExpiresAt: now.Add(s.cfg.SessionAbsolute),
	})
	if err != nil {
		return Session{}, fmt.Errorf("create visitor session: %w", err)
	}
	return Session{Token: token, ExpiresAt: row.AbsoluteExpiresAt, Email: row.Email, Name: row.Name}, nil
}

// SignIn creates the auth host's session for a verified identity.
func (s *Service) SignIn(ctx context.Context, id *identity.Identity, ip *netip.Addr) (Session, error) {
	if !id.EmailVerified || id.Email == "" {
		return Session{}, identity.ErrEmailNotVerified
	}
	email, err := apps.NormalizeEmail(id.Email)
	if err != nil {
		return Session{}, identity.ErrEmailNotVerified
	}
	var out Session
	err = s.store.InTx(ctx, func(q *store.Queries) error {
		var txErr error
		out, txErr = s.newSession(ctx, q, s.base.AuthHost(), nil, email, id.Name, id.Issuer, id.Subject)
		if txErr != nil {
			return txErr
		}
		return audit.Record(ctx, q, &audit.Entry{
			IP: ip, Action: audit.ActionVisitorSignIn, TargetType: "visitor", TargetID: email,
			Metadata: map[string]any{"issuer": id.Issuer},
		})
	})
	return out, err
}

// AuthSession returns the valid auth-host session for a token.
func (s *Service) AuthSession(ctx context.Context, token string) (store.VisitorSession, error) {
	return s.session(ctx, token, s.base.AuthHost())
}

func (s *Service) session(ctx context.Context, token, host string) (store.VisitorSession, error) {
	if !auth.LooksLikeSecret(token) {
		return store.VisitorSession{}, ErrInvalid
	}
	row, err := s.store.GetVisitorSession(ctx, auth.Hash(token))
	if store.IsNotFound(err) || (err == nil && row.Host != host) {
		return store.VisitorSession{}, ErrInvalid
	}
	if err != nil {
		return store.VisitorSession{}, fmt.Errorf("read visitor session: %w", err)
	}
	return row, nil
}

// IssueCode creates the single-use code that carries an auth-host session
// to one app host, with the (already validated) return path.
func (s *Service) IssueCode(ctx context.Context, app *store.App, host string, sess *store.VisitorSession, returnPath string) (string, error) {
	code := auth.NewSecret()
	err := s.store.CreateVisitorCode(ctx, store.CreateVisitorCodeParams{
		CodeHash: auth.Hash(code), Host: host, AppID: app.ID, Email: sess.Email, Name: sess.Name,
		Issuer: sess.Issuer, Subject: sess.Subject, ReturnPath: auth.SafeReturnPath(returnPath), ExpiresAt: s.now().Add(codeTTL),
	})
	if err != nil {
		return "", fmt.Errorf("issue visitor code: %w", err)
	}
	return code, nil
}

// Exchange redeems a code on the host it was issued for and returns the
// app host's new session and where to send the visitor.
func (s *Service) Exchange(ctx context.Context, code, host string) (Session, string, error) {
	if !auth.LooksLikeSecret(code) {
		return Session{}, "", ErrInvalid
	}
	var out Session
	var ret string
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		c, err := q.UseVisitorCode(ctx, store.UseVisitorCodeParams{CodeHash: auth.Hash(code), Host: host})
		if store.IsNotFound(err) {
			return ErrInvalid
		}
		if err != nil {
			return fmt.Errorf("redeem visitor code: %w", err)
		}
		ret = c.ReturnPath
		out, err = s.newSession(ctx, q, host, &c.AppID, c.Email, c.Name, c.Issuer, c.Subject)
		return err
	})
	return out, ret, err
}

// Check results.
const (
	CheckOK      = "ok"
	CheckDenied  = "denied"
	CheckInvalid = "invalid"
)

// Checked is the outcome of a session check.
type Checked struct {
	Status string
	Email  string
	Name   string
}

// Check validates an app host's session and decides access now, so a
// revoked grant or membership takes effect at the gateway's next check.
func (s *Service) Check(ctx context.Context, token, host string) (Checked, error) {
	row, err := s.session(ctx, token, host)
	if errors.Is(err, ErrInvalid) {
		return Checked{Status: CheckInvalid}, nil
	}
	if err != nil {
		return Checked{}, err
	}
	app, err := s.AppForHost(ctx, host)
	if errors.Is(err, ErrUnknownApp) || (err == nil && (row.AppID == nil || *row.AppID != app.ID)) {
		return Checked{Status: CheckInvalid}, nil
	}
	if err != nil {
		return Checked{}, err
	}
	ok, err := s.Allowed(ctx, &app, row.Email)
	if err != nil {
		return Checked{}, err
	}
	if err := s.store.TouchVisitorSession(ctx, store.TouchVisitorSessionParams{
		ID: row.ID, IdleSeconds: s.cfg.SessionIdle.Seconds(),
	}); err != nil {
		return Checked{}, fmt.Errorf("touch visitor session: %w", err)
	}
	status := CheckOK
	if !ok {
		status = CheckDenied
	}
	return Checked{Status: status, Email: row.Email, Name: row.Name}, nil
}

// SignOut revokes a session.
func (s *Service) SignOut(ctx context.Context, token string) error {
	if !auth.LooksLikeSecret(token) {
		return nil
	}
	if err := s.store.RevokeVisitorSession(ctx, auth.Hash(token)); err != nil {
		return fmt.Errorf("revoke visitor session: %w", err)
	}
	return nil
}

// Cleanup deletes long-expired sessions and codes (leader's janitor).
func (s *Service) Cleanup(ctx context.Context) error {
	if _, err := s.store.DeleteExpiredVisitorSessions(ctx); err != nil {
		return fmt.Errorf("delete expired visitor sessions: %w", err)
	}
	if _, err := s.store.DeleteExpiredVisitorCodes(ctx); err != nil {
		return fmt.Errorf("delete expired visitor codes: %w", err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
