package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/store"
)

// touchInterval throttles last-seen updates: at most one write per
// session (or token) per interval instead of one per request.
const touchInterval = time.Minute

// maxUserAgentLength matches the sessions.user_agent column constraint.
const maxUserAgentLength = 512

// Sessions manages browser sessions. The browser holds a random token in a
// cookie; the database holds only its SHA-256 digest, so a database leak
// does not leak usable sessions.
type Sessions struct {
	store *store.Store
	cfg   Config
}

// NewSessions returns a session manager.
func NewSessions(s *store.Store, cfg Config) *Sessions {
	return &Sessions{store: s, cfg: cfg}
}

// Create starts a session for userID using q (normally the sign-in
// transaction) and returns the raw token for the cookie. A brand-new token
// is always generated: Nook never adopts a session ID offered by the
// client, which is what defeats session fixation.
func (s *Sessions) Create(ctx context.Context, q *store.Queries, userID uuid.UUID, userAgent string, ip *netip.Addr) (string, store.Session, error) {
	raw := NewSecret()
	if len(userAgent) > maxUserAgentLength {
		userAgent = userAgent[:maxUserAgentLength]
	}
	sess, err := q.CreateSession(ctx, store.CreateSessionParams{
		UserID:          userID,
		TokenHash:       Hash(raw),
		IdleSeconds:     s.cfg.SessionIdleTimeout.Seconds(),
		AbsoluteSeconds: s.cfg.SessionAbsoluteTimeout.Seconds(),
		UserAgent:       userAgent,
		Ip:              ip,
	})
	if err != nil {
		return "", store.Session{}, fmt.Errorf("create session: %w", err)
	}
	return raw, sess, nil
}

// Authenticate resolves a raw session token to its principal.
func (s *Sessions) Authenticate(ctx context.Context, raw string) (*Principal, error) {
	if !LooksLikeSecret(raw) {
		return nil, ErrInvalidCredentials
	}
	row, err := s.store.GetActiveSession(ctx, Hash(raw))
	if store.IsNotFound(err) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("look up session: %w", err)
	}
	if time.Since(row.Session.LastSeenAt) > touchInterval {
		err := s.store.TouchSession(ctx, store.TouchSessionParams{
			ID:                 row.Session.ID,
			IdleSeconds:        s.cfg.SessionIdleTimeout.Seconds(),
			MinIntervalSeconds: touchInterval.Seconds(),
		})
		if err != nil {
			return nil, fmt.Errorf("touch session: %w", err)
		}
	}
	return &Principal{
		User:         row.User,
		Method:       MethodSession,
		CredentialID: row.Session.ID,
		CSRFToken:    CSRFToken(raw),
	}, nil
}

// Revoke ends a session by ID. Revoking an already revoked session is a no-op.
func (s *Sessions) Revoke(ctx context.Context, q *store.Queries, id uuid.UUID) error {
	if _, err := q.RevokeSession(ctx, id); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeRaw ends the session identified by a raw token, if it exists. It
// is used at sign-in to retire whatever session the browser had before.
func (s *Sessions) RevokeRaw(ctx context.Context, q *store.Queries, raw string) error {
	if !LooksLikeSecret(raw) {
		return nil
	}
	if _, err := q.RevokeSessionByTokenHash(ctx, Hash(raw)); err != nil {
		return fmt.Errorf("revoke previous session: %w", err)
	}
	return nil
}

// csrfContext domain-separates CSRF tokens from any other use of the key.
const csrfContext = "nook-csrf-v1"

// CSRFToken derives the CSRF token for a session: HMAC-SHA256 keyed with
// the raw session token. It is never stored, changes whenever the session
// does, and cannot be computed without the HttpOnly session cookie.
func CSRFToken(rawSession string) string {
	mac := hmac.New(sha256.New, []byte(rawSession))
	mac.Write([]byte(csrfContext))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ValidCSRFToken compares a presented token with the expected one in
// constant time.
func ValidCSRFToken(p *Principal, presented string) bool {
	if p == nil || p.Method != MethodSession || p.CSRFToken == "" || presented == "" {
		return false
	}
	return hmac.Equal([]byte(p.CSRFToken), []byte(presented))
}
