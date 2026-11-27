package secrets

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/the-asmit/nook/internal/audit"
	"github.com/the-asmit/nook/internal/store"
)

// Verify checks the keyring against the database before the server uses
// it: every version that encrypted stored values must be present, and
// every version with a recorded check value must be the same key. It then
// records a check value for the active version. A server started with a
// wrong or incomplete key fails here, clearly, instead of later.
func Verify(ctx context.Context, st *store.Store, k *Keyring) error {
	checks, err := st.ListSecretKeyChecks(ctx)
	if err != nil {
		return fmt.Errorf("read key checks: %w", err)
	}
	for _, c := range checks {
		v := int(c.Version)
		if k.Has(v) && !k.matches(v, c.CheckValue) {
			return fmt.Errorf("NOOK_SECRETS_KEY: key version %d is not the key that encrypted the stored values", v)
		}
	}
	used, err := st.KeyVersionsInUse(ctx)
	if err != nil {
		return fmt.Errorf("read key versions in use: %w", err)
	}
	var missing []string
	for _, v := range used {
		if !k.Has(int(v)) {
			missing = append(missing, strconv.Itoa(int(v)))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("NOOK_SECRETS_KEY: stored values are encrypted with key version(s) %v, which the keyring lacks", missing)
	}
	check, err := k.checkValue(k.active)
	if err != nil {
		return err
	}
	if err := st.InsertSecretKeyCheck(ctx, store.InsertSecretKeyCheckParams{Version: int32(k.active), CheckValue: check}); err != nil { //nolint:gosec // G115: versions are at most 1e6.
		return fmt.Errorf("record key check: %w", err)
	}
	return nil
}

// rotateBatch bounds the rows re-encrypted per transaction.
const rotateBatch = 500

// Rotate re-encrypts every stored value (current variables and deployment
// snapshots) that is not under the active key version, and returns how
// many it rewrote. Each value is decrypted and sealed again with the same
// binding; a value whose old version is missing from the keyring stops
// the rotation with an error. It is safe to run again after a failure and
// while servers are running (rows changed meanwhile are skipped by their
// version check and picked up by the next batch).
func Rotate(ctx context.Context, st *store.Store, k *Keyring) (int, error) {
	if err := Verify(ctx, st, k); err != nil {
		return 0, err
	}
	total := 0
	for _, batch := range []func(context.Context, *store.Store, *Keyring) (int, int, error){rotateEnv, rotateSnapshots, rotateCerts, rotateDBPasswords, rotateDBServers} {
		for {
			seen, n, err := batch(ctx, st, k)
			total += n
			if err != nil {
				return total, err
			}
			if seen == 0 {
				break
			}
		}
	}
	err := st.InTx(ctx, func(q *store.Queries) error {
		return audit.Record(ctx, q, &audit.Entry{
			Action: audit.ActionSecretsRotate, TargetType: "secrets", TargetID: strconv.Itoa(k.active),
			Metadata: map[string]any{"active_version": k.active, "values_reencrypted": total},
		})
	})
	return total, err
}

var errNothing = errors.New("no rows")

func rotateEnv(ctx context.Context, st *store.Store, k *Keyring) (seen, n int, err error) {
	err = st.InTx(ctx, func(q *store.Queries) error {
		rows, listErr := q.ListAppEnvNotOnVersion(ctx, store.ListAppEnvNotOnVersionParams{Version: int32(k.active), RowLimit: rotateBatch}) //nolint:gosec // G115: versions are at most 1e6.
		if listErr != nil {
			return fmt.Errorf("list values: %w", listErr)
		}
		if len(rows) == 0 {
			return errNothing
		}
		seen = len(rows)
		for _, r := range rows {
			aad := EnvAAD(r.AppID, r.Key)
			plain, openErr := k.Open(int(r.KeyVersion), aad, r.Value)
			if openErr != nil {
				return fmt.Errorf("variable %s of app %s (key version %d): %w", r.Key, r.AppID, r.KeyVersion, openErr)
			}
			sealed, v, sealErr := k.Seal(aad, plain)
			clear(plain)
			if sealErr != nil {
				return sealErr
			}
			c, updErr := q.ReencryptAppEnv(ctx, store.ReencryptAppEnvParams{
				AppID: r.AppID, Key: r.Key, Value: sealed, KeyVersion: int32(v), OldVersion: r.KeyVersion, //nolint:gosec // G115: versions are at most 1e6.
			})
			if updErr != nil {
				return fmt.Errorf("store value: %w", updErr)
			}
			n += int(c)
		}
		return nil
	})
	if errors.Is(err, errNothing) {
		return 0, 0, nil
	}
	return seen, n, err
}

func rotateSnapshots(ctx context.Context, st *store.Store, k *Keyring) (seen, n int, err error) {
	err = st.InTx(ctx, func(q *store.Queries) error {
		rows, listErr := q.ListSnapshotVarsNotOnVersion(ctx, store.ListSnapshotVarsNotOnVersionParams{Version: int32(k.active), RowLimit: rotateBatch}) //nolint:gosec // G115: versions are at most 1e6.
		if listErr != nil {
			return fmt.Errorf("list snapshot values: %w", listErr)
		}
		if len(rows) == 0 {
			return errNothing
		}
		seen = len(rows)
		for _, r := range rows {
			aad := EnvAAD(r.AppID, r.Key)
			plain, openErr := k.Open(int(r.KeyVersion), aad, r.Value)
			if openErr != nil {
				return fmt.Errorf("snapshot variable %s of app %s (key version %d): %w", r.Key, r.AppID, r.KeyVersion, openErr)
			}
			sealed, v, sealErr := k.Seal(aad, plain)
			clear(plain)
			if sealErr != nil {
				return sealErr
			}
			c, updErr := q.ReencryptSnapshotVar(ctx, store.ReencryptSnapshotVarParams{
				SnapshotID: r.SnapshotID, Key: r.Key, Value: sealed, KeyVersion: int32(v), OldVersion: r.KeyVersion, //nolint:gosec // G115: versions are at most 1e6.
			})
			if updErr != nil {
				return fmt.Errorf("store snapshot value: %w", updErr)
			}
			n += int(c)
		}
		return nil
	})
	if errors.Is(err, errNothing) {
		return 0, 0, nil
	}
	return seen, n, err
}

// AddKey returns the keyring text with a new, highest version appended.
func AddKey(current string) (string, int, error) {
	k, err := ParseKeyring(current)
	if err != nil {
		return "", 0, err
	}
	next := slices.Max(k.Versions()) + 1
	line, err := NewKeyLine(next)
	if err != nil {
		return "", 0, err
	}
	out := current
	if out != "" && out[len(out)-1] != '\n' {
		out += "\n"
	}
	return out + line + "\n", next, nil
}

func rotateCerts(ctx context.Context, st *store.Store, k *Keyring) (seen, n int, err error) {
	err = st.InTx(ctx, func(q *store.Queries) error {
		rows, listErr := q.ListGatewayCertificatesNotOnVersion(ctx, store.ListGatewayCertificatesNotOnVersionParams{Version: int32(k.active), RowLimit: rotateBatch}) //nolint:gosec // G115: versions are at most 1e6.
		if listErr != nil {
			return fmt.Errorf("list gateway certificates: %w", listErr)
		}
		if len(rows) == 0 {
			return errNothing
		}
		seen = len(rows)
		for _, r := range rows {
			aad := CertAAD(r.Name)
			plain, openErr := k.Open(int(r.KeyVersion), aad, r.Data)
			if openErr != nil {
				return fmt.Errorf("gateway certificate %s (key version %d): %w", r.Name, r.KeyVersion, openErr)
			}
			sealed, v, sealErr := k.Seal(aad, plain)
			clear(plain)
			if sealErr != nil {
				return sealErr
			}
			c, updErr := q.ReencryptGatewayCertificate(ctx, store.ReencryptGatewayCertificateParams{
				Name: r.Name, Data: sealed, KeyVersion: int32(v), OldVersion: r.KeyVersion, //nolint:gosec // G115: versions are at most 1e6.
			})
			if updErr != nil {
				return fmt.Errorf("store gateway certificate: %w", updErr)
			}
			n += int(c)
		}
		return nil
	})
	if errors.Is(err, errNothing) {
		return 0, 0, nil
	}
	return seen, n, err
}

// rotateDBPasswords re-encrypts app database passwords. (App database
// backups stay encrypted with the key derived from the version recorded
// on their server, which therefore stays in use.)
func rotateDBPasswords(ctx context.Context, st *store.Store, k *Keyring) (seen, n int, err error) {
	err = st.InTx(ctx, func(q *store.Queries) error {
		rows, listErr := q.ListAppDatabasesNotOnVersion(ctx, store.ListAppDatabasesNotOnVersionParams{Version: int32(k.active), RowLimit: rotateBatch}) //nolint:gosec // G115: versions are at most 1e6.
		if listErr != nil {
			return fmt.Errorf("list app database passwords: %w", listErr)
		}
		if len(rows) == 0 {
			return errNothing
		}
		seen = len(rows)
		for _, r := range rows {
			c, rerr := reseal(k, DatabasePasswordAAD(r.AppID), int(r.PasswordKeyVersion), r.Password, func(sealed []byte, v int) (int64, error) {
				return q.ReencryptAppDatabasePassword(ctx, store.ReencryptAppDatabasePasswordParams{
					AppID: r.AppID, Password: sealed, NewVersion: int32(v), OldVersion: r.PasswordKeyVersion, //nolint:gosec // G115: versions are at most 1e6.
				})
			})
			if rerr != nil {
				return fmt.Errorf("app database password of %s: %w", r.AppID, rerr)
			}
			n += int(c)
		}
		return nil
	})
	if errors.Is(err, errNothing) {
		return 0, 0, nil
	}
	return seen, n, err
}

// rotateDBServers re-encrypts the database servers' superuser passwords.
func rotateDBServers(ctx context.Context, st *store.Store, k *Keyring) (seen, n int, err error) {
	err = st.InTx(ctx, func(q *store.Queries) error {
		rows, listErr := q.ListDBServersNotOnVersion(ctx, store.ListDBServersNotOnVersionParams{Version: int32(k.active), RowLimit: rotateBatch}) //nolint:gosec // G115: versions are at most 1e6.
		if listErr != nil {
			return fmt.Errorf("list database server passwords: %w", listErr)
		}
		if len(rows) == 0 {
			return errNothing
		}
		seen = len(rows)
		for _, r := range rows {
			c, rerr := reseal(k, DatabaseSuperuserAAD(r.ID), int(r.PasswordKeyVersion), r.SuperuserPassword, func(sealed []byte, v int) (int64, error) {
				return q.ReencryptDBServerPassword(ctx, store.ReencryptDBServerPasswordParams{
					ID: r.ID, SuperuserPassword: sealed, NewVersion: int32(v), OldVersion: r.PasswordKeyVersion, //nolint:gosec // G115: versions are at most 1e6.
				})
			})
			if rerr != nil {
				return fmt.Errorf("database server password of %s: %w", r.ID, rerr)
			}
			n += int(c)
		}
		return nil
	})
	if errors.Is(err, errNothing) {
		return 0, 0, nil
	}
	return seen, n, err
}

// reseal opens a value sealed with version v and stores it sealed with the
// active version through save.
func reseal(k *Keyring, aad []byte, v int, sealed []byte, save func([]byte, int) (int64, error)) (int64, error) {
	plain, err := k.Open(v, aad, sealed)
	if err != nil {
		return 0, fmt.Errorf("key version %d: %w", v, err)
	}
	out, nv, err := k.Seal(aad, plain)
	clear(plain)
	if err != nil {
		return 0, err
	}
	return save(out, nv)
}
