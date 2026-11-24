// Package device implements the OAuth 2.0 Device Authorization Grant
// (RFC 8628) that the CLI uses to sign in: the CLI gets a device code and
// a short user code, the person approves the user code in a signed-in
// browser, and the CLI's polling then receives an API token exactly once.
package device

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/store"
)

// Config holds device-flow timings.
type Config struct {
	// CodeTTL is how long a device code stays usable.
	CodeTTL time.Duration `env:"NOOK_DEVICE_CODE_TTL" envDefault:"10m"`
	// PollInterval is the minimum time between polls the CLI is told to keep.
	PollInterval time.Duration `env:"NOOK_DEVICE_POLL_INTERVAL" envDefault:"5s"`
	// TokenTTL is the lifetime of API tokens issued to the CLI.
	TokenTTL time.Duration `env:"NOOK_CLI_TOKEN_TTL" envDefault:"2160h"`
}

// Validate checks the timings.
func (c *Config) Validate() error {
	return errors.Join(
		config.CheckDuration("NOOK_DEVICE_CODE_TTL", c.CodeTTL, time.Minute, time.Hour),
		config.CheckDuration("NOOK_DEVICE_POLL_INTERVAL", c.PollInterval, time.Second, time.Minute),
		config.CheckDuration("NOOK_CLI_TOKEN_TTL", c.TokenTTL, time.Hour, 366*24*time.Hour),
	)
}

// slowDownStep is how much the interval grows after each too-fast poll
// (RFC 8628 section 3.5).
const slowDownStep = 5

// maxIntervalSeconds matches the poll_interval_seconds column constraint.
const maxIntervalSeconds = 300

// Poll outcomes other than success, using the RFC 8628 error codes.
var (
	ErrAuthorizationPending = &apperr.Error{Kind: apperr.KindInvalid, Code: "authorization_pending", Message: "the user has not approved the request yet"}
	ErrSlowDown             = &apperr.Error{Kind: apperr.KindInvalid, Code: "slow_down", Message: "polling too fast; increase the interval by 5 seconds"}
	ErrAccessDenied         = &apperr.Error{Kind: apperr.KindInvalid, Code: "access_denied", Message: "the user denied the request"}
	ErrExpiredToken         = &apperr.Error{Kind: apperr.KindInvalid, Code: "expired_token", Message: "the device code has expired; start again"}
	// ErrInvalidGrant covers unknown codes and codes already redeemed.
	ErrInvalidGrant = &apperr.Error{Kind: apperr.KindInvalid, Code: "invalid_grant", Message: "unknown or already used device code"}
)

// Started is the response to a new device authorization request.
type Started struct {
	DeviceCode string
	UserCode   string // display form, "BDFG-HJKL"
	ExpiresIn  time.Duration
	Interval   time.Duration
}

// Issued is the result of a successful poll.
type Issued struct {
	Token    string
	APIToken store.ApiToken
}

// Service runs the device flow.
type Service struct {
	store  *store.Store
	tokens *auth.APITokens
	cfg    Config
}

// NewService returns a device-flow service.
func NewService(s *store.Store, tokens *auth.APITokens, cfg Config) *Service {
	return &Service{store: s, tokens: tokens, cfg: cfg}
}

// NormalizeClientName validates the client description shown to the user
// on the approval page ("nook CLI on laptop").
func NormalizeClientName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "nook CLI"
	}
	if utf8.RuneCountInString(s) > 100 {
		return "", apperr.Invalid("invalid_client_name", "client_name must be at most 100 characters")
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return "", apperr.Invalid("invalid_client_name", "client_name must be printable text")
		}
	}
	return s, nil
}

// Start creates a device authorization request.
func (s *Service) Start(ctx context.Context, clientName string) (Started, error) {
	clientName, err := NormalizeClientName(clientName)
	if err != nil {
		return Started{}, err
	}
	deviceCode := auth.NewSecret()
	// A fresh user code can collide with a pending one; retry a few times.
	for range 5 {
		userCode := auth.NewUserCode()
		_, err := s.store.CreateDeviceAuthorization(ctx, store.CreateDeviceAuthorizationParams{
			DeviceCodeHash: auth.Hash(deviceCode),
			UserCode:       userCode,
			ClientName:     clientName,
			TtlSeconds:     s.cfg.CodeTTL.Seconds(),
			// Validation bounds the interval to 1-60 s.
			PollIntervalSeconds: int32(s.cfg.PollInterval / time.Second), //nolint:gosec // G115: bounded by Config.Validate.
		})
		if store.IsUniqueViolation(err, "device_authorizations_pending_user_code_key") {
			continue
		}
		if err != nil {
			return Started{}, fmt.Errorf("create device authorization: %w", err)
		}
		return Started{
			DeviceCode: deviceCode,
			UserCode:   auth.FormatUserCode(userCode),
			ExpiresIn:  s.cfg.CodeTTL,
			Interval:   s.cfg.PollInterval,
		}, nil
	}
	return Started{}, errors.New("could not allocate a unique user code")
}

// Poll is called by the CLI with its device code. It returns the issued
// token once the request is approved, and an RFC 8628 error otherwise.
//
// Non-success outcomes are not transaction failures: the poll bookkeeping
// (last poll time, a slowed-down interval, the expired status) must be
// committed, so they travel out of the transaction in outcome.
func (s *Service) Poll(ctx context.Context, deviceCode string) (Issued, error) {
	if !auth.LooksLikeSecret(deviceCode) {
		return Issued{}, ErrInvalidGrant
	}
	var (
		issued  Issued
		outcome error
	)
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		row, err := q.GetDeviceAuthorizationForPoll(ctx, auth.Hash(deviceCode))
		if store.IsNotFound(err) {
			outcome = ErrInvalidGrant
			return nil
		}
		if err != nil {
			return fmt.Errorf("load device authorization: %w", err)
		}
		d := row.DeviceAuthorization
		switch {
		case d.Status == store.DeviceStatusConsumed:
			outcome = ErrInvalidGrant
			return nil
		case d.Status == store.DeviceStatusExpired:
			outcome = ErrExpiredToken
			return nil
		case row.IsExpired && d.Status == store.DeviceStatusPending:
			outcome = ErrExpiredToken
			err = q.MarkDeviceAuthorizationExpired(ctx, d.ID)
			if err != nil {
				return fmt.Errorf("expire device authorization: %w", err)
			}
			return nil
		case d.Status == store.DeviceStatusDenied:
			outcome = ErrAccessDenied
			return nil
		}

		interval := d.PollIntervalSeconds
		if row.PolledTooSoon {
			interval = min(interval+slowDownStep, maxIntervalSeconds)
		}
		err = q.RecordDevicePoll(ctx, store.RecordDevicePollParams{ID: d.ID, PollIntervalSeconds: interval})
		if err != nil {
			return fmt.Errorf("record poll: %w", err)
		}
		switch {
		case row.PolledTooSoon:
			outcome = ErrSlowDown
			return nil
		case d.Status == store.DeviceStatusPending:
			outcome = ErrAuthorizationPending
			return nil
		}
		// Approved: issuing the token and consuming the request commit
		// together or not at all.
		issued, err = s.issue(ctx, q, &d)
		return err
	})
	if err != nil {
		return Issued{}, err
	}
	if outcome != nil {
		return Issued{}, outcome
	}
	return issued, nil
}

// issue mints the API token for an approved request and marks it consumed.
func (s *Service) issue(ctx context.Context, q *store.Queries, d *store.DeviceAuthorization) (Issued, error) {
	expires := time.Now().Add(s.cfg.TokenTTL)
	name := "CLI: " + d.ClientName
	if utf8.RuneCountInString(name) > 100 {
		name = string([]rune(name)[:100])
	}
	raw, tok, err := s.tokens.Create(ctx, q, *d.UserID, name, &expires)
	if err != nil {
		return Issued{}, err
	}
	n, err := q.ConsumeDeviceAuthorization(ctx, store.ConsumeDeviceAuthorizationParams{ID: d.ID, ApiTokenID: &tok.ID})
	if err != nil {
		return Issued{}, fmt.Errorf("consume device authorization: %w", err)
	}
	if n != 1 {
		return Issued{}, ErrInvalidGrant
	}
	return Issued{Token: raw, APIToken: tok}, audit.Record(ctx, q, &audit.Entry{
		ActorID: d.UserID, Action: audit.ActionTokenCreate, TargetType: audit.TargetAPIToken, TargetID: tok.ID.String(),
		Metadata: map[string]any{"name": tok.Name, "via": "device_flow", "device_authorization_id": d.ID.String()},
	})
}
