package auth

import (
	"context"
	"errors"
	"uuid"

	"github.com/the-asmit/nook/internal/store"
)

// Method says how a request was authenticated.
type Method string

// Authentication methods.
const (
	MethodSession Method = "session"
	MethodToken   Method = "token"
)

// Principal is the authenticated caller of a request.
type Principal struct {
	User   store.User
	Method Method
	// CredentialID is the session ID or API token ID that authenticated
	// the request, so logout can revoke exactly that credential.
	CredentialID uuid.UUID
	// CSRFToken is set for session-authenticated requests; state-changing
	// requests must echo it back.
	CSRFToken string
}

// ErrInvalidCredentials means credentials were presented but are unknown,
// expired, revoked or belong to a disabled user. Callers must not reveal
// which of these applies.
var ErrInvalidCredentials = errors.New("invalid or expired credentials")

type principalKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal stored in ctx, if any.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}
