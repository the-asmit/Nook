package auth

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
)

// MaxTokenLifetime caps the expiry users can choose for a token.
const MaxTokenLifetime = 366 * 24 * time.Hour

// NormalizeTokenName validates a token's display name.
func NormalizeTokenName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 100 {
		return "", apperr.Invalid("invalid_name", "token name must be 1 to 100 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", apperr.Invalid("invalid_name", "token name must not contain control characters")
		}
	}
	return name, nil
}

// CreateForUser issues a named token for scripts and CI. A nil lifetime
// means the token never expires.
func (t *APITokens) CreateForUser(ctx context.Context, userID uuid.UUID, ip *netip.Addr, name string, lifetime *time.Duration) (string, store.ApiToken, error) {
	name, err := NormalizeTokenName(name)
	if err != nil {
		return "", store.ApiToken{}, err
	}
	var expires *time.Time
	if lifetime != nil {
		if *lifetime < time.Hour || *lifetime > MaxTokenLifetime {
			return "", store.ApiToken{}, apperr.Invalid("invalid_expiry", "expiry must be between 1 hour and 366 days")
		}
		e := time.Now().Add(*lifetime)
		expires = &e
	}
	var (
		raw string
		tok store.ApiToken
	)
	err = t.store.InTx(ctx, func(q *store.Queries) error {
		raw, tok, err = t.Create(ctx, q, userID, name, expires)
		if err != nil {
			return err
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &userID, IP: ip,
			Action: audit.ActionTokenCreate, TargetType: audit.TargetAPIToken, TargetID: tok.ID.String(),
			Metadata: map[string]any{"name": tok.Name, "via": "api", "expires_at": tok.ExpiresAt},
		})
	})
	return raw, tok, err
}

// List returns the user's tokens, newest first, before the given ID.
func (t *APITokens) List(ctx context.Context, userID, before uuid.UUID, limit int32) ([]store.ApiToken, error) {
	toks, err := t.store.ListAPITokens(ctx, store.ListAPITokensParams{UserID: userID, BeforeID: before, RowLimit: limit})
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	return toks, nil
}

// Revoke revokes one of the user's own tokens. Revoking a token that is
// already revoked, does not exist, or belongs to someone else changes
// nothing and is not an error (idempotent, and reveals nothing).
func (t *APITokens) Revoke(ctx context.Context, userID uuid.UUID, ip *netip.Addr, id uuid.UUID) error {
	return t.store.InTx(ctx, func(q *store.Queries) error {
		tok, err := q.RevokeAPIToken(ctx, store.RevokeAPITokenParams{ID: id, UserID: userID})
		if store.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("revoke api token: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &userID, IP: ip,
			Action: audit.ActionTokenRevoke, TargetType: audit.TargetAPIToken, TargetID: tok.ID.String(),
			Metadata: map[string]any{"name": tok.Name},
		})
	})
}

// Logout revokes the credential that authenticated p: the browser session,
// or the API token (which is how `nook logout` invalidates the CLI's token).
func Logout(ctx context.Context, s *store.Store, p *Principal, ip *netip.Addr) error {
	return s.InTx(ctx, func(q *store.Queries) error {
		target := audit.TargetSession
		if p.Method == MethodToken {
			target = audit.TargetAPIToken
			if _, err := q.RevokeAPIToken(ctx, store.RevokeAPITokenParams{ID: p.CredentialID, UserID: p.User.ID}); err != nil && !store.IsNotFound(err) {
				return fmt.Errorf("revoke api token: %w", err)
			}
		} else if _, err := q.RevokeSession(ctx, p.CredentialID); err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: &p.User.ID, IP: ip,
			Action: audit.ActionSignOut, TargetType: target, TargetID: p.CredentialID.String(),
			Metadata: map[string]any{"method": p.Method},
		})
	})
}
