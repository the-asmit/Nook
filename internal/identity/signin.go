package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// Sign-in refusals. Each maps to a page explaining what happened.
var (
	// ErrEmailNotVerified means the provider did not vouch for the email.
	ErrEmailNotVerified = errors.New("the identity provider has not verified this email address")
	// ErrNotInvited means the person may not create an account here.
	ErrNotInvited = errors.New("this email address is not allowed to sign in")
	// ErrUserDisabled means the account exists but was disabled.
	ErrUserDisabled = errors.New("this account is disabled")
	// ErrEmailInUse means another identity already owns this email. Accounts
	// are never linked by email: that would let anyone who controls an
	// address at a second provider take over the account.
	ErrEmailInUse = errors.New("this email address belongs to a different account")
)

// Policy decides who may create an account.
type Policy struct {
	domains   []string
	bootstrap []string
}

// NewPolicy builds the policy from configuration.
func NewPolicy(cfg *Config) Policy {
	lower := func(in []string) []string {
		out := make([]string, len(in))
		for i, s := range in {
			out[i] = strings.ToLower(strings.TrimSpace(s))
		}
		return out
	}
	return Policy{domains: lower(cfg.AllowedEmailDomains), bootstrap: lower(cfg.BootstrapAdminEmails)}
}

// IsBootstrapAdmin reports whether email is a configured bootstrap admin.
func (p Policy) IsBootstrapAdmin(email string) bool {
	return slices.Contains(p.bootstrap, strings.ToLower(email))
}

// DomainAllowed reports whether email's domain is on the allow-list. Only
// exact domain matches count; subdomains must be listed explicitly.
func (p Policy) DomainAllowed(email string) bool {
	at := strings.LastIndexByte(email, '@')
	return at > 0 && slices.Contains(p.domains, strings.ToLower(email[at+1:]))
}

// RequestMeta is information about the browser signing in.
type RequestMeta struct {
	UserAgent string
	IP        *netip.Addr
	// PreviousSession is the raw session cookie the browser already had,
	// if any; it is revoked so each sign-in starts a fresh session.
	PreviousSession string
}

// SignInResult is a successful sign-in.
type SignInResult struct {
	User       store.User
	RawSession string
	Session    store.Session
	NewUser    bool
}

// Service signs people in.
type Service struct {
	store    *store.Store
	sessions *auth.Sessions
	policy   Policy
	logger   *slog.Logger
}

// NewService returns a sign-in service.
func NewService(s *store.Store, sessions *auth.Sessions, policy Policy, logger *slog.Logger) *Service {
	return &Service{store: s, sessions: sessions, policy: policy, logger: logger}
}

// SignIn admits a verified identity: it creates or updates the user,
// accepts their open invitations, rotates their session and audits it, all
// in one transaction, so a refused sign-in leaves nothing behind.
func (s *Service) SignIn(ctx context.Context, ident *Identity, meta RequestMeta) (SignInResult, error) {
	id := *ident
	if !id.EmailVerified {
		return SignInResult{}, ErrEmailNotVerified
	}
	if id.Email == "" || len(id.Email) > 254 || !strings.Contains(id.Email, "@") {
		return SignInResult{}, ErrEmailNotVerified
	}
	id.Name = truncateRunes(id.Name, 200)
	if len(id.Picture) > 2048 || !strings.HasPrefix(id.Picture, "https://") {
		id.Picture = ""
	}

	var res SignInResult
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		user, isNew, err := s.upsertUser(ctx, q, &id, meta.IP)
		if err != nil {
			return err
		}
		err = workspace.AcceptInvitations(ctx, q, &user, meta.IP)
		if err != nil {
			return err
		}
		err = s.sessions.RevokeRaw(ctx, q, meta.PreviousSession)
		if err != nil {
			return err
		}
		raw, sess, err := s.sessions.Create(ctx, q, user.ID, meta.UserAgent, meta.IP)
		if err != nil {
			return err
		}
		res = SignInResult{User: user, RawSession: raw, Session: sess, NewUser: isNew}
		return audit.Record(ctx, q, &audit.Entry{
			ActorID: audit.Ptr(user.ID), IP: meta.IP,
			Action: audit.ActionSignIn, TargetType: audit.TargetSession, TargetID: sess.ID.String(),
			Metadata: map[string]any{"new_user": isNew},
		})
	})
	if store.IsUniqueViolation(err, "users_email_key") {
		return SignInResult{}, ErrEmailInUse
	}
	return res, err
}

// upsertUser returns the existing user for the identity (refreshing their
// profile) or creates one if the policy admits them.
func (s *Service) upsertUser(ctx context.Context, q *store.Queries, id *Identity, ip *netip.Addr) (store.User, bool, error) {
	bootstrap := s.policy.IsBootstrapAdmin(id.Email)
	existing, err := q.GetUserByIdentity(ctx, store.GetUserByIdentityParams{OidcIssuer: id.Issuer, OidcSubject: id.Subject})
	switch {
	case err == nil:
		user, refreshErr := refreshUser(ctx, q, &existing, id, bootstrap, ip)
		return user, false, refreshErr
	case !store.IsNotFound(err):
		return store.User{}, false, fmt.Errorf("look up user: %w", err)
	}

	invited, err := q.HasOpenInvitation(ctx, id.Email)
	if err != nil {
		return store.User{}, false, fmt.Errorf("check invitations: %w", err)
	}
	if !bootstrap && !invited && !s.policy.DomainAllowed(id.Email) {
		// Log the domain only: the full address is personal data of
		// someone who has no account here.
		s.logger.WarnContext(ctx, "sign-in refused: not invited", "email_domain", emailDomain(id.Email))
		return store.User{}, false, ErrNotInvited
	}

	user, err := q.CreateUser(ctx, store.CreateUserParams{
		Email: id.Email, Name: id.Name, AvatarUrl: id.Picture,
		OidcIssuer: id.Issuer, OidcSubject: id.Subject, IsInstanceAdmin: bootstrap,
	})
	if err != nil {
		return store.User{}, false, fmt.Errorf("create user: %w", err)
	}
	err = audit.Record(ctx, q, &audit.Entry{
		ActorID: audit.Ptr(user.ID), IP: ip,
		Action: audit.ActionUserCreate, TargetType: audit.TargetUser, TargetID: user.ID.String(),
		Metadata: map[string]any{"email": user.Email, "issuer": id.Issuer, "invited": invited},
	})
	if err != nil {
		return store.User{}, false, err
	}
	if bootstrap {
		err = recordAdminGrant(ctx, q, &user, ip)
		if err != nil {
			return store.User{}, false, err
		}
	}
	_, err = workspace.CreatePersonal(ctx, q, &user, ip)
	if err != nil {
		return store.User{}, false, err
	}
	return user, true, nil
}

// refreshUser updates a returning user's profile from the provider.
//
// The allow-list gates account creation only. People admitted by
// invitation keep access after their invitation is used up; access is
// withdrawn by disabling the account.
func refreshUser(ctx context.Context, q *store.Queries, existing *store.User, id *Identity, bootstrap bool, ip *netip.Addr) (store.User, error) {
	if existing.DisabledAt != nil {
		return store.User{}, ErrUserDisabled
	}
	user, err := q.RecordUserSignIn(ctx, store.RecordUserSignInParams{
		ID: existing.ID, Email: id.Email, Name: id.Name, AvatarUrl: id.Picture, GrantInstanceAdmin: bootstrap,
	})
	if err != nil {
		return store.User{}, fmt.Errorf("update user: %w", err)
	}
	if user.IsInstanceAdmin && !existing.IsInstanceAdmin {
		if err := recordAdminGrant(ctx, q, &user, ip); err != nil {
			return store.User{}, err
		}
	}
	return user, nil
}

func recordAdminGrant(ctx context.Context, q *store.Queries, user *store.User, ip *netip.Addr) error {
	return audit.Record(ctx, q, &audit.Entry{
		ActorID: audit.Ptr(user.ID), IP: ip,
		Action: audit.ActionInstanceAdminGrant, TargetType: audit.TargetUser, TargetID: user.ID.String(),
		Metadata: map[string]any{"reason": "bootstrap_admin"},
	})
}

func emailDomain(email string) string {
	if at := strings.LastIndexByte(email, '@'); at >= 0 {
		return strings.ToLower(email[at+1:])
	}
	return ""
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
