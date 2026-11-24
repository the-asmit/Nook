package identity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"

	"github.com/the-asmit/nook/internal/auth"
)

// FlowTTL bounds how long a person may spend at the identity provider.
const FlowTTL = 10 * time.Minute

// FlowCookie is the base name of the cookie binding a sign-in attempt to
// the browser that started it.
const FlowCookie = "nook_signin"

// Flow is the server-side state of one sign-in attempt.
type Flow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	ReturnTo string `json:"return_to"`
}

// ErrFlowNotFound means the sign-in attempt is unknown, expired or was
// already completed.
var ErrFlowNotFound = errors.New("sign-in attempt not found or expired")

// Flows stores sign-in attempts in Redis. The browser holds only a random
// flow ID in an HttpOnly cookie; state, nonce and PKCE verifier never leave
// the server, and each attempt can be completed exactly once.
type Flows struct {
	redis *goredis.Client
}

// NewFlows returns a flow store.
func NewFlows(client *goredis.Client) *Flows {
	return &Flows{redis: client}
}

// Begin creates a sign-in attempt and returns its ID (for the cookie).
func (f *Flows) Begin(ctx context.Context, returnTo string) (string, Flow, error) {
	id := auth.NewSecret()
	flow := Flow{
		State:    auth.NewSecret(),
		Nonce:    auth.NewSecret(),
		Verifier: oauth2.GenerateVerifier(),
		ReturnTo: auth.SafeReturnPath(returnTo),
	}
	data, err := json.Marshal(flow)
	if err != nil {
		return "", Flow{}, fmt.Errorf("encode sign-in flow: %w", err)
	}
	if err := f.redis.Set(ctx, flowKey(id), data, FlowTTL).Err(); err != nil {
		return "", Flow{}, fmt.Errorf("store sign-in flow: %w", err)
	}
	return id, flow, nil
}

// Take returns and deletes the attempt with the given ID (single use).
func (f *Flows) Take(ctx context.Context, id string) (Flow, error) {
	if !auth.LooksLikeSecret(id) {
		return Flow{}, ErrFlowNotFound
	}
	data, err := f.redis.GetDel(ctx, flowKey(id)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return Flow{}, ErrFlowNotFound
	}
	if err != nil {
		return Flow{}, fmt.Errorf("load sign-in flow: %w", err)
	}
	var flow Flow
	if err := json.Unmarshal(data, &flow); err != nil {
		return Flow{}, fmt.Errorf("decode sign-in flow: %w", err)
	}
	return flow, nil
}

// flowKey stores attempts under a digest of their ID, so reading Redis
// does not reveal live cookie values.
func flowKey(id string) string {
	return "nook:signin:" + hex.EncodeToString(auth.Hash(id))
}
