package auth

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/store"
)

// APITokens issues and verifies personal access tokens for the CLI and
// scripts.
type APITokens struct {
	store *store.Store
}

// NewAPITokens returns a token manager.
func NewAPITokens(s *store.Store) *APITokens {
	return &APITokens{store: s}
}

// Create issues a token for userID using q and returns the raw token. The
// raw value exists only in this return value: it is shown to the user once
// and only its digest is stored.
func (t *APITokens) Create(ctx context.Context, q *store.Queries, userID uuid.UUID, name string, expiresAt *time.Time) (string, store.ApiToken, error) {
	raw, prefix := NewAPIToken()
	tok, err := q.CreateAPIToken(ctx, store.CreateAPITokenParams{
		UserID:    userID,
		Name:      name,
		TokenHash: Hash(raw),
		Prefix:    prefix,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", store.ApiToken{}, fmt.Errorf("create api token: %w", err)
	}
	return raw, tok, nil
}

// Authenticate resolves a raw API token to its principal.
func (t *APITokens) Authenticate(ctx context.Context, raw string) (*Principal, error) {
	if !LooksLikeAPIToken(raw) {
		return nil, ErrInvalidCredentials
	}
	row, err := t.store.GetActiveAPIToken(ctx, Hash(raw))
	if store.IsNotFound(err) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("look up api token: %w", err)
	}
	if last := row.ApiToken.LastUsedAt; last == nil || time.Since(*last) > touchInterval {
		err := t.store.TouchAPIToken(ctx, store.TouchAPITokenParams{
			ID:                 row.ApiToken.ID,
			MinIntervalSeconds: touchInterval.Seconds(),
		})
		if err != nil {
			return nil, fmt.Errorf("touch api token: %w", err)
		}
	}
	return &Principal{User: row.User, Method: MethodToken, CredentialID: row.ApiToken.ID}, nil
}
