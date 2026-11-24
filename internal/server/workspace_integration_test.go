//go:build integration

package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"testing"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/identity"
	"github.com/the-asmit/nook/internal/store"
)

// user is a signed-up user with an API token for calling the API.
type user struct {
	id    uuid.UUID
	email string
	token string
	// personal is the slug of their personal workspace.
	personal string
}

// newUser signs a user up through the real sign-in service (with an
// identity as the OIDC provider would assert it) and gives them an API
// token. The OIDC protocol itself is covered by the Dex-based tests.
func (e *env) newUser(email string) user {
	e.t.Helper()
	ctx := context.Background()
	st := store.NewStore(e.db)
	sessions := auth.NewSessions(st, auth.Config{SessionIdleTimeout: time.Hour, SessionAbsoluteTimeout: 2 * time.Hour})
	svc := identity.NewService(st, sessions, identity.NewPolicy(&identity.Config{AllowedEmailDomains: []string{"nook.test"}}),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	res, err := svc.SignIn(ctx, &identity.Identity{
		Issuer: shared.dex.IssuerURL, Subject: "sub-" + email, Email: email, EmailVerified: true,
	}, identity.RequestMeta{})
	if err != nil {
		e.t.Fatalf("sign up %s: %v", email, err)
	}
	raw, _, err := auth.NewAPITokens(st).Create(ctx, st.Queries, res.User.ID, "test", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	var slug string
	if err := e.db.QueryRow(ctx, "SELECT slug FROM workspaces WHERE personal_owner_id = $1", res.User.ID).Scan(&slug); err != nil {
		e.t.Fatal(err)
	}
	return user{id: res.User.ID, email: email, token: raw, personal: slug}
}

func (e *env) as(u user, method, path string, body any) response {
	e.t.Helper()
	return e.bearer(u.token, method, path, body)
}

func expectStatus(t *testing.T, r response, want int, what string) {
	t.Helper()
	if r.status != want {
		t.Errorf("%s: status %d, want %d: %s", what, r.status, want, r.body)
	}
}

// TestTenantIsolation proves that a user can neither read nor change a
// workspace they do not belong to, and cannot even learn that it exists.
func TestTenantIsolation(t *testing.T) {
	e := startEnv(t)
	alice, mallory := e.newUser("alice@nook.test"), e.newUser("mallory@nook.test")

	expectStatus(t, e.as(alice, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Secret", "slug": "secret"}), 201, "create")
	inv := e.as(alice, http.MethodPost, "/api/v1/workspaces/secret/invitations", map[string]string{"email": "carol@nook.test"})
	var invitation struct {
		ID string `json:"id"`
	}
	inv.json(t, &invitation)
	aliceID := alice.id.String()

	attempts := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/workspaces/secret", nil},
		{http.MethodPatch, "/api/v1/workspaces/secret", map[string]string{"name": "pwned"}},
		{http.MethodDelete, "/api/v1/workspaces/secret", nil},
		{http.MethodGet, "/api/v1/workspaces/secret/members", nil},
		{http.MethodPatch, "/api/v1/workspaces/secret/members/" + aliceID, map[string]string{"role": "member"}},
		{http.MethodDelete, "/api/v1/workspaces/secret/members/" + aliceID, nil},
		{http.MethodGet, "/api/v1/workspaces/secret/invitations", nil},
		{http.MethodPost, "/api/v1/workspaces/secret/invitations", map[string]string{"email": "mallory2@nook.test", "role": "owner"}},
		{http.MethodDelete, "/api/v1/workspaces/secret/invitations/" + invitation.ID, nil},
		{http.MethodGet, "/api/v1/workspaces/" + alice.personal, nil},
		{http.MethodDelete, "/api/v1/workspaces/" + alice.personal, nil},
	}
	for _, a := range attempts {
		got := e.as(mallory, a.method, a.path, a.body)
		missing := e.as(mallory, a.method, replaceSlug(a.path, "does-not-exist"), a.body)
		if got.status != http.StatusNotFound || got.errorCode(t) != "not_found" {
			t.Errorf("%s %s by a non-member: %d %s", a.method, a.path, got.status, got.body)
		}
		// Identical answers for "not yours" and "does not exist".
		if got.status != missing.status || got.errorCode(t) != missing.errorCode(t) {
			t.Errorf("%s %s leaks existence: %d vs %d", a.method, a.path, got.status, missing.status)
		}
	}

	// Nothing changed.
	if n := e.count("SELECT count(*) FROM workspaces WHERE slug = 'secret' AND name = 'Secret'"); n != 1 {
		t.Fatal("workspace was modified or deleted")
	}
	if n := e.count("SELECT count(*) FROM memberships WHERE user_id = $1", mallory.id); n != 1 {
		t.Fatal("mallory gained a membership")
	}
	if n := e.count("SELECT count(*) FROM invitations"); n != 1 {
		t.Fatal("invitations changed")
	}

	// The workspace list shows only one's own workspaces.
	var list struct {
		Items []struct {
			Slug string `json:"slug"`
		} `json:"items"`
	}
	e.as(mallory, http.MethodGet, "/api/v1/workspaces", nil).json(t, &list)
	if len(list.Items) != 1 || list.Items[0].Slug != mallory.personal {
		t.Fatalf("mallory sees %+v", list.Items)
	}
}

func replaceSlug(path, slug string) string {
	const prefix = "/api/v1/workspaces/"
	rest := path[len(prefix):]
	for i := range len(rest) {
		if rest[i] == '/' {
			return prefix + slug + rest[i:]
		}
	}
	return prefix + slug
}

func TestTokensAreIsolatedPerUser(t *testing.T) {
	e := startEnv(t)
	alice, mallory := e.newUser("alice@nook.test"), e.newUser("mallory@nook.test")
	var tokens struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	e.as(alice, http.MethodGet, "/api/v1/tokens", nil).json(t, &tokens)
	if len(tokens.Items) != 1 {
		t.Fatalf("alice tokens = %+v", tokens.Items)
	}
	// Revoking someone else's token "succeeds" (idempotent, reveals nothing) but does nothing.
	expectStatus(t, e.as(mallory, http.MethodDelete, "/api/v1/tokens/"+tokens.Items[0].ID, nil), 204, "foreign revoke")
	expectStatus(t, e.as(alice, http.MethodGet, "/api/v1/me", nil), 200, "alice's token after foreign revoke")
	e.as(mallory, http.MethodGet, "/api/v1/tokens", nil).json(t, &tokens)
	if len(tokens.Items) != 1 || tokens.Items[0].ID == "" {
		t.Fatal("token list not scoped to its owner")
	}
}

func TestRoleRules(t *testing.T) {
	e := startEnv(t)
	owner, admin, member := e.newUser("owner@nook.test"), e.newUser("admin@nook.test"), e.newUser("member@nook.test")
	expectStatus(t, e.as(owner, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": "Team", "slug": "team"}), 201, "create")
	// Admit admin and member through invitations, as in real life.
	for _, u := range []struct {
		u    user
		role string
	}{{admin, "admin"}, {member, "member"}} {
		expectStatus(t, e.as(owner, http.MethodPost, "/api/v1/workspaces/team/invitations", map[string]string{"email": u.u.email, "role": u.role}), 201, "invite")
	}
	e.newUserSignIn(admin.email)
	e.newUserSignIn(member.email)

	ws := "/api/v1/workspaces/team"
	t.Run("member reads but cannot manage", func(t *testing.T) {
		expectStatus(t, e.as(member, http.MethodGet, ws+"/members", nil), 200, "list members")
		expectStatus(t, e.as(member, http.MethodPatch, ws, map[string]string{"name": "x"}), 403, "rename")
		expectStatus(t, e.as(member, http.MethodGet, ws+"/invitations", nil), 403, "list invitations")
		expectStatus(t, e.as(member, http.MethodPost, ws+"/invitations", map[string]string{"email": "x@nook.test"}), 403, "invite")
		expectStatus(t, e.as(member, http.MethodDelete, ws+"/members/"+admin.id.String(), nil), 403, "remove admin")
		expectStatus(t, e.as(member, http.MethodDelete, ws, nil), 403, "delete")
	})
	t.Run("admin manages members but not owners", func(t *testing.T) {
		expectStatus(t, e.as(admin, http.MethodPatch, ws, map[string]string{"name": "Team 2"}), 200, "rename")
		expectStatus(t, e.as(admin, http.MethodPost, ws+"/invitations", map[string]string{"email": "o@nook.test", "role": "owner"}), 403, "invite owner")
		expectStatus(t, e.as(admin, http.MethodPatch, ws+"/members/"+member.id.String(), map[string]string{"role": "owner"}), 403, "promote to owner")
		expectStatus(t, e.as(admin, http.MethodPatch, ws+"/members/"+owner.id.String(), map[string]string{"role": "member"}), 403, "demote owner")
		expectStatus(t, e.as(admin, http.MethodDelete, ws+"/members/"+owner.id.String(), nil), 403, "remove owner")
		expectStatus(t, e.as(admin, http.MethodPatch, ws+"/members/"+member.id.String(), map[string]string{"role": "admin"}), 204, "promote member")
		expectStatus(t, e.as(admin, http.MethodPatch, ws+"/members/"+member.id.String(), map[string]string{"role": "member"}), 204, "demote admin")
		expectStatus(t, e.as(admin, http.MethodPatch, ws+"/members/"+member.id.String(), map[string]string{"role": "root"}), 400, "invalid role")
		expectStatus(t, e.as(admin, http.MethodDelete, ws, nil), 403, "delete")
	})
	t.Run("last owner is protected", func(t *testing.T) {
		r := e.as(owner, http.MethodPatch, ws+"/members/"+owner.id.String(), map[string]string{"role": "admin"})
		if r.status != 409 || r.errorCode(t) != "last_owner" {
			t.Fatalf("demote last owner: %d %s", r.status, r.body)
		}
		r = e.as(owner, http.MethodDelete, ws+"/members/"+owner.id.String(), nil)
		if r.status != 409 || r.errorCode(t) != "last_owner" {
			t.Fatalf("last owner leaves: %d %s", r.status, r.body)
		}
		expectStatus(t, e.as(owner, http.MethodPatch, ws+"/members/"+admin.id.String(), map[string]string{"role": "owner"}), 204, "promote admin to owner")
		expectStatus(t, e.as(owner, http.MethodDelete, ws+"/members/"+owner.id.String(), nil), 204, "leave once another owner exists")
		if n := e.count("SELECT count(*) FROM memberships m JOIN workspaces w ON w.id = m.workspace_id WHERE w.slug = 'team' AND m.role = 'owner'"); n != 1 {
			t.Fatalf("owners = %d", n)
		}
	})
	t.Run("idempotent deletes", func(t *testing.T) {
		expectStatus(t, e.as(admin, http.MethodDelete, ws+"/members/"+uuid.NewV7().String(), nil), 204, "remove non-member")
		expectStatus(t, e.as(admin, http.MethodDelete, ws+"/invitations/"+uuid.NewV7().String(), nil), 204, "revoke missing invitation")
		expectStatus(t, e.as(admin, http.MethodDelete, ws+"/members/not-a-uuid", nil), 404, "malformed id")
	})
	t.Run("workspace deletion", func(t *testing.T) {
		// member also belongs to "team", so their personal workspace may go.
		r := e.as(member, http.MethodDelete, "/api/v1/workspaces/"+member.personal, nil)
		expectStatus(t, r, 204, "personal workspace deletable when user has another")
		// A user whose personal workspace is their only one cannot delete it.
		lonely := e.newUser("lonely@nook.test")
		r = e.as(lonely, http.MethodDelete, "/api/v1/workspaces/"+lonely.personal, nil)
		if r.status != 409 || r.errorCode(t) != "last_workspace" {
			t.Fatalf("delete only workspace: %d %s", r.status, r.body)
		}
		expectStatus(t, e.as(admin, http.MethodDelete, ws, nil), 204, "owner deletes")
		expectStatus(t, e.as(admin, http.MethodDelete, ws, nil), 404, "delete again")
	})

	actions := e.auditActions()
	for _, want := range []string{"workspace.create", "workspace.update", "invitation.create", "invitation.accept",
		"member.role_change", "member.remove", "workspace.delete"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit log lacks %s", want)
		}
	}
}

// newUserSignIn signs an existing user in again (accepting invitations).
func (e *env) newUserSignIn(email string) {
	e.t.Helper()
	st := store.NewStore(e.db)
	svc := identity.NewService(st, auth.NewSessions(st, auth.Config{SessionIdleTimeout: time.Hour, SessionAbsoluteTimeout: 2 * time.Hour}),
		identity.NewPolicy(&identity.Config{AllowedEmailDomains: []string{"nook.test"}}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := svc.SignIn(context.Background(), &identity.Identity{
		Issuer: shared.dex.IssuerURL, Subject: "sub-" + email, Email: email, EmailVerified: true,
	}, identity.RequestMeta{}); err != nil {
		e.t.Fatal(err)
	}
}

func TestInvitationRules(t *testing.T) {
	e := startEnv(t)
	owner := e.newUser("owner@nook.test")
	path := "/api/v1/workspaces/" + owner.personal + "/invitations"
	expectStatus(t, e.as(owner, http.MethodPost, path, map[string]string{"email": "x@nook.test"}), 201, "invite")
	r := e.as(owner, http.MethodPost, path, map[string]string{"email": "X@nook.test"})
	if r.status != 409 || r.errorCode(t) != "invitation_exists" {
		t.Fatalf("duplicate (case-insensitive) invitation: %d %s", r.status, r.body)
	}
	r = e.as(owner, http.MethodPost, path, map[string]string{"email": owner.email})
	if r.status != 409 || r.errorCode(t) != "already_member" {
		t.Fatalf("inviting a member: %d %s", r.status, r.body)
	}
	expectStatus(t, e.as(owner, http.MethodPost, path, map[string]string{"email": "Name <x@nook.test>"}), 400, "display-name email")
	// An expired open invitation does not block a new one.
	e.exec("UPDATE invitations SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'")
	expectStatus(t, e.as(owner, http.MethodPost, path, map[string]string{"email": "x@nook.test"}), 201, "re-invite after expiry")
}

func TestListPagination(t *testing.T) {
	e := startEnv(t)
	u := e.newUser("pager@nook.test")
	for _, slug := range []string{"aa", "bb", "cc", "dd"} {
		expectStatus(t, e.as(u, http.MethodPost, "/api/v1/workspaces", map[string]string{"name": slug, "slug": slug}), 201, "create")
	}
	var seen []string
	path := "/api/v1/workspaces?limit=2"
	for range 10 {
		var page struct {
			Items []struct {
				Slug string `json:"slug"`
			} `json:"items"`
			NextCursor *string `json:"next_cursor"`
		}
		e.as(u, http.MethodGet, path, nil).json(t, &page)
		if len(page.Items) > 2 {
			t.Fatalf("page larger than limit: %d", len(page.Items))
		}
		for _, it := range page.Items {
			seen = append(seen, it.Slug)
		}
		if page.NextCursor == nil {
			break
		}
		path = "/api/v1/workspaces?limit=2&cursor=" + *page.NextCursor
	}
	if !slices.Equal(seen, []string{"aa", "bb", "cc", "dd", u.personal}) {
		t.Fatalf("pages = %v", seen)
	}
	expectStatus(t, e.as(u, http.MethodGet, "/api/v1/workspaces?cursor=garbage", nil), 400, "bad cursor")
}

func TestAPITokenLifecycle(t *testing.T) {
	e := startEnv(t)
	u := e.newUser("tok@nook.test")
	r := e.as(u, http.MethodPost, "/api/v1/tokens", map[string]any{"name": "ci", "expires_in_days": 30})
	var created struct {
		Token    string `json:"token"`
		Metadata struct {
			ID     string `json:"id"`
			Prefix string `json:"prefix"`
		} `json:"metadata"`
	}
	r.json(t, &created)
	if r.status != 201 || created.Token[:13] != created.Metadata.Prefix {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	if n := e.count("SELECT count(*) FROM api_tokens WHERE token_hash = sha256($1::bytea)", []byte(created.Token)); n != 1 {
		t.Fatal("token not stored as its SHA-256 digest")
	}
	expectStatus(t, e.bearer(created.Token, http.MethodGet, "/api/v1/me", nil), 200, "use new token")
	if n := e.count("SELECT count(*) FROM api_tokens WHERE last_used_at IS NOT NULL AND id = $1", created.Metadata.ID); n != 1 {
		t.Fatal("last_used_at not recorded")
	}

	expectStatus(t, e.as(u, http.MethodDelete, "/api/v1/tokens/"+created.Metadata.ID, nil), 204, "revoke")
	expectStatus(t, e.as(u, http.MethodDelete, "/api/v1/tokens/"+created.Metadata.ID, nil), 204, "revoke again")
	expectStatus(t, e.bearer(created.Token, http.MethodGet, "/api/v1/me", nil), 401, "revoked token")

	e.exec("UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE user_id = $1 AND revoked_at IS NULL", u.id)
	expectStatus(t, e.as(u, http.MethodGet, "/api/v1/me", nil), 401, "expired token")

	for _, bad := range []map[string]any{{"name": ""}, {"name": "x", "expires_in_days": 0}, {"name": "x", "expires_in_days": 400}} {
		u2 := e.newUser("tok2-" + time.Now().Format("150405.000000") + "@nook.test")
		expectStatus(t, e.as(u2, http.MethodPost, "/api/v1/tokens", bad), 400, "invalid token request")
	}
	actions := e.auditActions()
	if !slices.Contains(actions, "token.create") || !slices.Contains(actions, "token.revoke") {
		t.Fatalf("token actions not audited: %v", actions)
	}
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	e := startEnv(t)
	e.newUser("audit@nook.test")
	ctx := context.Background()
	for _, stmt := range []string{"UPDATE audit_log SET action = 'x.y'", "DELETE FROM audit_log", "TRUNCATE audit_log"} {
		if _, err := e.db.Exec(ctx, stmt); err == nil {
			t.Errorf("%q succeeded on the append-only audit log", stmt)
		}
	}
	if n := e.count("SELECT count(*) FROM audit_log"); n == 0 {
		t.Fatal("audit entries disappeared")
	}
}
