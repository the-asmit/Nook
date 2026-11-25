package apps

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
	"github.com/the-asmit/nook/internal/workspace"
)

// Limits on environment variables.
const (
	maxEnvValueBytes = 32 << 10
	maxEnvVars       = 200
	maxEnvTotalBytes = 256 << 10
	maxEnvPerRequest = 50
)

// envKeyPattern is the POSIX portable environment variable name.
var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// ReservedEnvKeys are set by Nook in every container (PORT, NOOK_APP,
// NOOK_DEPLOYMENT); the whole NOOK_ prefix is reserved for Nook.
var ReservedEnvKeys = []string{"PORT", "NOOK_APP", "NOOK_DEPLOYMENT"}

// validateEnvKey checks a variable name.
func validateEnvKey(k string) error {
	if !envKeyPattern.MatchString(k) {
		return apperr.Invalid("invalid_env_key", "%q is not a valid variable name (letters, digits and _, not starting with a digit, at most 128 characters)", truncateKey(k))
	}
	if slices.Contains(ReservedEnvKeys, k) || strings.HasPrefix(k, "NOOK_") {
		return apperr.Invalid("reserved_env_key", "%s is set by Nook and cannot be changed (PORT, NOOK_APP, NOOK_DEPLOYMENT and every NOOK_ name are reserved)", k)
	}
	return nil
}

// validateEnvValue checks a value without ever echoing it.
func validateEnvValue(k, v string) error {
	switch {
	case len(v) > maxEnvValueBytes:
		return apperr.Invalid("env_value_too_large", "the value of %s is larger than %d bytes", k, maxEnvValueBytes)
	case !utf8.ValidString(v):
		return apperr.Invalid("invalid_env_value", "the value of %s is not valid UTF-8", k)
	case strings.ContainsRune(v, 0):
		return apperr.Invalid("invalid_env_value", "the value of %s contains a NUL character", k)
	}
	return nil
}

func truncateKey(k string) string {
	if len(k) > 40 {
		return k[:40] + "…"
	}
	return k
}

// EnvVar is a variable as listed: secret values are never returned.
type EnvVar struct {
	Key       string
	Value     string
	Secret    bool
	UpdatedAt time.Time
}

// ListEnv returns the app's variables; values of secrets are omitted.
func (s *Service) ListEnv(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string) ([]EnvVar, error) {
	_, app, err := resolve(ctx, s.store.Queries, actor, wsSlug, appSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListAppEnv(ctx, app.ID)
	if err != nil {
		return nil, fmt.Errorf("list variables: %w", err)
	}
	out := make([]EnvVar, 0, len(rows))
	for _, r := range rows {
		v := EnvVar{Key: r.Key, Secret: r.IsSecret, UpdatedAt: r.UpdatedAt}
		if !r.IsSecret {
			plain, err := s.keyring.Open(int(r.KeyVersion), secrets.EnvAAD(app.ID, r.Key), r.Value)
			if err != nil {
				return nil, fmt.Errorf("variable %s: %w", r.Key, err)
			}
			v.Value = string(plain)
		}
		out = append(out, v)
	}
	return out, nil
}

// EnvChange is the result of changing variables.
type EnvChange struct {
	// Deployment releases the change, when the app has a live deployment.
	Deployment *store.Deployment
}

// SetEnv sets variables. Members may set plain variables; setting a
// secret, or overwriting one, needs an admin or owner. If the app has a
// live deployment, a new deployment of the same image with the new
// environment is created and released (no rebuild).
func (s *Service) SetEnv(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string, vars map[string]string, secret bool) (EnvChange, error) {
	if len(vars) == 0 || len(vars) > maxEnvPerRequest {
		return EnvChange{}, apperr.Invalid("invalid_env", "set between 1 and %d variables at once", maxEnvPerRequest)
	}
	keys := slices.Sorted(maps.Keys(vars))
	for _, k := range keys {
		if err := validateEnvKey(k); err != nil {
			return EnvChange{}, err
		}
		if err := validateEnvValue(k, vars[k]); err != nil {
			return EnvChange{}, err
		}
	}
	return s.changeEnv(ctx, actor, wsSlug, appSlug, func(q *store.Queries, v workspace.View, app *store.App, current map[string]store.AppEnv) error {
		admin := v.Allows(store.WorkspaceRoleAdmin)
		for _, k := range keys {
			if (secret || current[k].IsSecret) && !admin {
				return apperr.Forbidden("only workspace admins and owners can set or change secrets")
			}
		}
		total, count := envSize(current, vars)
		if count > maxEnvVars || total > maxEnvTotalBytes {
			return apperr.Invalid("env_too_large", "an app may have at most %d variables of %d bytes in total", maxEnvVars, maxEnvTotalBytes)
		}
		for _, k := range keys {
			sealed, version, err := s.keyring.Seal(secrets.EnvAAD(app.ID, k), []byte(vars[k]))
			if err != nil {
				return err
			}
			if err := q.UpsertAppEnv(ctx, store.UpsertAppEnvParams{
				AppID: app.ID, Key: k, Value: sealed, KeyVersion: int32(version), IsSecret: secret, UpdatedBy: &actor.UserID, //nolint:gosec // G115: versions are at most 1e6.
			}); err != nil {
				return fmt.Errorf("store variable: %w", err)
			}
		}
		// Names and the secret flag only: values never reach the audit log.
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionEnvSet, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{"app": app.Slug, "keys": keys, "secret": secret},
		})
	})
}

// UnsetEnv removes a variable; removing a secret needs an admin or owner.
func (s *Service) UnsetEnv(ctx context.Context, actor workspace.Actor, wsSlug, appSlug, key string) (EnvChange, error) {
	if !envKeyPattern.MatchString(key) {
		return EnvChange{}, apperr.NotFound("variable not found")
	}
	return s.changeEnv(ctx, actor, wsSlug, appSlug, func(q *store.Queries, v workspace.View, app *store.App, current map[string]store.AppEnv) error {
		cur, ok := current[key]
		if !ok {
			return apperr.NotFound("variable not found")
		}
		if cur.IsSecret && !v.Allows(store.WorkspaceRoleAdmin) {
			return apperr.Forbidden("only workspace admins and owners can remove secrets")
		}
		if _, err := q.DeleteAppEnv(ctx, store.DeleteAppEnvParams{AppID: app.ID, Key: key}); err != nil {
			return fmt.Errorf("delete variable: %w", err)
		}
		return audit.Record(ctx, q, &audit.Entry{
			WorkspaceID: &v.Workspace.ID, ActorID: &actor.UserID, IP: actor.IP,
			Action: audit.ActionEnvUnset, TargetType: audit.TargetApp, TargetID: app.ID.String(),
			Metadata: map[string]any{"app": app.Slug, "key": key, "secret": cur.IsSecret},
		})
	})
}

// changeEnv runs change with the app locked and, if the app has a live
// deployment, creates the deployment that releases the new environment.
func (s *Service) changeEnv(ctx context.Context, actor workspace.Actor, wsSlug, appSlug string,
	change func(*store.Queries, workspace.View, *store.App, map[string]store.AppEnv) error) (EnvChange, error) {
	var out EnvChange
	err := s.store.InTx(ctx, func(q *store.Queries) error {
		v, app, err := resolve(ctx, q, actor, wsSlug, appSlug)
		if err != nil {
			return err
		}
		if app, err = q.LockApp(ctx, app.ID); err != nil {
			return fmt.Errorf("lock app: %w", err)
		}
		rows, err := q.ListAppEnv(ctx, app.ID)
		if err != nil {
			return fmt.Errorf("list variables: %w", err)
		}
		current := make(map[string]store.AppEnv, len(rows))
		for _, r := range rows {
			current[r.Key] = r
		}
		if changeErr := change(q, v, &app, current); changeErr != nil {
			return changeErr
		}
		if app.CurrentDeploymentID == nil {
			return nil // the next deployment takes the new environment
		}
		d, err := s.configDeployment(ctx, q, &app, *app.CurrentDeploymentID, actor.UserID)
		if err != nil {
			return err
		}
		out.Deployment = &d
		return nil
	})
	if err != nil {
		return EnvChange{}, err
	}
	if out.Deployment != nil {
		s.release(ctx, out.Deployment.ID)
	}
	return out, nil
}

// configDeployment creates a deployment of the live deployment's image
// with a snapshot of the app's current environment.
func (s *Service) configDeployment(ctx context.Context, q *store.Queries, app *store.App, liveID, userID uuid.UUID) (store.Deployment, error) {
	live, err := q.GetDeploymentByID(ctx, liveID)
	if err != nil {
		return store.Deployment{}, fmt.Errorf("read live deployment: %w", err)
	}
	snap, err := q.CreateEnvSnapshot(ctx, store.CreateEnvSnapshotParams{AppID: app.ID, CreatedBy: &userID})
	if err != nil {
		return store.Deployment{}, fmt.Errorf("create environment snapshot: %w", err)
	}
	if err = q.CopyEnvToSnapshot(ctx, store.CopyEnvToSnapshotParams{SnapshotID: snap.ID, AppID: app.ID}); err != nil {
		return store.Deployment{}, fmt.Errorf("copy environment: %w", err)
	}
	number, err := q.NextDeploymentNumber(ctx, app.ID)
	if err != nil {
		return store.Deployment{}, fmt.Errorf("next deployment number: %w", err)
	}
	d, err := q.CreateReleaseDeployment(ctx, store.CreateReleaseDeploymentParams{
		AppID: app.ID, Number: number, Kind: store.DeploymentKindConfig, ImageOfDeploymentID: &live.ID, EnvSnapshotID: &snap.ID,
		SourceKey: live.SourceKey, SourceSha256: live.SourceSha256, SourceSize: live.SourceSize,
		ImageDigest: live.ImageDigest, CreatedBy: &userID,
	})
	if err != nil {
		return store.Deployment{}, fmt.Errorf("create deployment: %w", err)
	}
	return d, nil
}

// envSize returns the total value size and count after applying set.
func envSize(current map[string]store.AppEnv, set map[string]string) (total, count int) {
	for k, r := range current {
		if _, replaced := set[k]; !replaced {
			// Ciphertexts carry a 28-byte nonce and tag.
			total += max(len(r.Value)-28, 0)
			count++
		}
	}
	for _, v := range set {
		total += len(v)
		count++
	}
	return total, count
}
