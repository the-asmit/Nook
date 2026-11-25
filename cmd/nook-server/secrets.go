package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/postgres"
	"github.com/the-asmit/nook/internal/secrets"
	"github.com/the-asmit/nook/internal/store"
)

// rotateConfig is what `secrets rotate-key` needs: the database and the
// keyring (normally NOOK_SECRETS_KEY_FILE), the same values the server uses.
type rotateConfig struct {
	Postgres postgres.Config
	Secrets  secrets.Config
}

// Validate checks the configuration.
func (c *rotateConfig) Validate() error {
	return errors.Join(c.Postgres.Validate(), c.Secrets.Validate())
}

//nolint:gosec // G101: usage text, not a credential.
const secretsUsage = `usage: nook-server secrets <command>

  init --out PATH       create a keyring file with a new key (version 1)
  add-key --path PATH   append a new key version to a keyring file; deploy
                        the file to every server and restart them before
                        running rotate-key
  rotate-key            re-encrypt every stored value with the newest key
                        in NOOK_SECRETS_KEY (or NOOK_SECRETS_KEY_FILE)
`

// runSecrets implements `nook-server secrets`. Key material is written
// only to files (mode 0600) and never printed.
func runSecrets(args []string, environ map[string]string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, secretsUsage)
		return 2
	}
	switch args[0] {
	case "init":
		return secretsInit(args[1:], stdout, stderr)
	case "add-key":
		return secretsAddKey(args[1:], stdout, stderr)
	case "rotate-key":
		return secretsRotate(environ, stdout, stderr)
	default:
		_, _ = fmt.Fprint(stderr, secretsUsage)
		return 2
	}
}

func secretsInit(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("secrets init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	out := flags.String("out", "", "keyring file to create (required; must not exist)")
	if err := flags.Parse(args); err != nil || *out == "" {
		_, _ = fmt.Fprintln(stderr, "secrets init: --out is required")
		return 2
	}
	line, err := secrets.NewKeyLine(1)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets init: %v\n", err)
		return 1
	}
	content := "# Nook master keys: <version>:<base64 key>. The highest version encrypts.\n" + line + "\n"
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets init: %v\n", err)
		return 1
	}
	_, err = f.WriteString(content)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets init: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "created %s with key version 1; point NOOK_SECRETS_KEY_FILE at it\n", *out)
	return 0
}

func secretsAddKey(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("secrets add-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("path", "", "keyring file to extend (required)")
	if err := flags.Parse(args); err != nil || *path == "" {
		_, _ = fmt.Fprintln(stderr, "secrets add-key: --path is required")
		return 2
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets add-key: %v\n", err)
		return 1
	}
	updated, version, err := secrets.AddKey(string(data))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets add-key: %s: %v\n", *path, err)
		return 1
	}
	if err := writePrivateFile(*path, []byte(updated)); err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets add-key: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "added key version %d to %s; restart every nook-server with it, then run `nook-server secrets rotate-key`\n", version, *path)
	return 0
}

// writePrivateFile replaces path atomically with a 0600 file.
func writePrivateFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keyring-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// rotateTimeout bounds a whole rotation run.
const rotateTimeout = 30 * time.Minute

func secretsRotate(environ map[string]string, stdout, stderr io.Writer) int {
	cfg, err := config.Load[rotateConfig](environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets rotate-key: invalid configuration: %v\n", err)
		return 2
	}
	keyring, err := cfg.Secrets.Keyring()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets rotate-key: NOOK_SECRETS_KEY: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, rotateTimeout)
	defer cancel()
	pool, err := postgres.NewPool(ctx, &cfg.Postgres, "nook-server-secrets")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets rotate-key: %v\n", err)
		return 1
	}
	defer pool.Close()
	n, err := secrets.Rotate(ctx, store.NewStore(pool), keyring)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "secrets rotate-key: re-encrypted %d values, then failed: %v\n", n, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "re-encrypted %d values with key version %d; every stored value now uses it\n", n, keyring.Active())
	return 0
}
