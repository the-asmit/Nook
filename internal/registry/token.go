// Package registry integrates Nook with its private OCI image registry
// (CNCF Distribution): it issues the short-lived, repository-scoped bearer
// tokens the registry accepts, and talks to the registry API to manage
// stored images.
//
// The registry runs with token authentication. It trusts tokens signed by
// a key whose certificate chains to Nook's internal CA; the certificate
// travels in the token header (x5c). Only the control plane holds such a
// key, and it hands tokens only to authenticated agents (over mTLS) for
// the one repository a build pushes to.
package registry

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/the-asmit/nook/internal/pki"
)

// Actions a token may grant on a repository.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
)

// Access is one grant in a token: actions on a resource.
type Access struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// RepositoryAccess grants actions on one repository.
func RepositoryAccess(repo string, actions ...string) Access {
	return Access{Type: "repository", Name: repo, Actions: actions}
}

// CatalogAccess grants listing all repositories.
func CatalogAccess() Access {
	return Access{Type: "registry", Name: "catalog", Actions: []string{"*"}}
}

// signerTTL is the lifetime of the token-signing certificate; a new one
// is issued well before it expires.
const signerTTL = 7 * 24 * time.Hour

// Issuer signs registry tokens.
type Issuer struct {
	ca      *pki.CA
	issuer  string
	service string
	now     func() time.Time

	mu     sync.Mutex
	signer *pki.Signer
}

// NewIssuer returns an issuer whose tokens name issuer and service; both
// must match the registry's auth.token configuration.
func NewIssuer(ca *pki.CA, issuer, service string) *Issuer {
	return &Issuer{ca: ca, issuer: issuer, service: service, now: time.Now}
}

func (i *Issuer) currentSigner(now time.Time) (*pki.Signer, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.signer == nil || i.signer.Cert.NotAfter.Sub(now) < signerTTL/2 {
		s, err := i.ca.IssueSigner("nook registry token signer", signerTTL)
		if err != nil {
			return nil, err
		}
		i.signer = s
	}
	return i.signer, nil
}

// Token returns a signed token for subject granting access, valid for ttl.
func (i *Issuer) Token(subject string, ttl time.Duration, access ...Access) (string, error) {
	now := i.now()
	signer, err := i.currentSigner(now)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("token id: %w", err)
	}
	header := map[string]any{
		"typ": "JWT",
		"alg": "ES256",
		"x5c": []string{base64.StdEncoding.EncodeToString(signer.Cert.Raw)},
	}
	if access == nil {
		access = []Access{}
	}
	claims := map[string]any{
		"iss":    i.issuer,
		"sub":    subject,
		"aud":    i.service,
		"iat":    now.Unix(),
		"nbf":    now.Add(-time.Minute).Unix(),
		"exp":    now.Add(ttl).Unix(),
		"jti":    base64.RawURLEncoding.EncodeToString(jti),
		"access": access,
	}
	return signJWT(signer.Key, header, claims)
}

func signJWT(key *ecdsa.PrivateKey, header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("encode token header: %w", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode token claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	// JWS ES256 signatures are the fixed-width big-endian r || s.
	sig := make([]byte, 64)
	fillBig(sig[:32], r)
	fillBig(sig[32:], s)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func fillBig(dst []byte, n *big.Int) {
	n.FillBytes(dst)
}
