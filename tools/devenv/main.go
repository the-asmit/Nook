// Command devenv creates or updates the git-ignored .env file used for
// local development (run it with `make env`).
//
// A missing .env becomes a copy of .env.example. An existing .env keeps
// every value it has; variables that .env.example gained since are
// appended. In both cases these placeholders are filled in:
//
//	__GENERATED_SECRET__   128 random bits, hex-encoded
//	__BCRYPT:NAME__        bcrypt hash of the value of variable NAME
//	                       (for Dex's static development users)
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("devenv", flag.ContinueOnError)
	example := flags.String("example", ".env.example", "template file")
	out := flags.String("out", ".env", "file to create or update")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	tmpl, err := os.ReadFile(*example)
	if err != nil {
		fmt.Fprintln(os.Stderr, "devenv:", err)
		return 1
	}
	existing, err := os.ReadFile(*out)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "devenv:", err)
		return 1
	}
	result, added, err := Sync(tmpl, existing, defaultGenerator, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "devenv:", err)
		return 1
	}
	if len(added) == 0 {
		return 0
	}
	if err := writePrivate(*out, result); err != nil {
		fmt.Fprintln(os.Stderr, "devenv:", err)
		return 1
	}
	fmt.Printf("devenv: wrote %d variable(s) to %s: %s\n", len(added), *out, strings.Join(added, ", "))
	return 0
}

// Generator produces the values for placeholders.
type Generator struct {
	Secret func() string
	Bcrypt func(password string) (string, error)
}

var defaultGenerator = Generator{
	Secret: func() string {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	},
	Bcrypt: func(password string) (string, error) {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		return string(h), err
	},
}

var (
	assignment  = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)=(.*)$`)
	bcryptToken = regexp.MustCompile(`^__BCRYPT:([A-Z][A-Z0-9_]*)__$`)
)

const secretToken = "__GENERATED_SECRET__" //nolint:gosec // G101: a placeholder marker, not a secret.

// Sync returns the new contents of the env file and the names of the
// variables it added. existing may be empty (no file yet).
func Sync(tmpl, existing []byte, gen Generator, now time.Time) ([]byte, []string, error) {
	values := parseValues(existing)
	var added []string
	resolve := func(key, raw string) (string, error) {
		v, err := fill(raw, values, gen)
		if err != nil {
			return "", fmt.Errorf("%s: %w", key, err)
		}
		values[key] = unquote(v)
		added = append(added, key)
		return v, nil
	}

	var out bytes.Buffer
	if len(bytes.TrimSpace(existing)) == 0 {
		// New file: the template with placeholders filled, comments kept.
		sc := bufio.NewScanner(bytes.NewReader(tmpl))
		for sc.Scan() {
			line := sc.Text()
			if m := assignment.FindStringSubmatch(line); m != nil {
				v, err := resolve(m[1], m[2])
				if err != nil {
					return nil, nil, err
				}
				line = m[1] + "=" + v
			}
			out.WriteString(line + "\n")
		}
		return out.Bytes(), added, sc.Err()
	}

	out.Write(existing)
	if !bytes.HasSuffix(existing, []byte("\n")) {
		out.WriteByte('\n')
	}
	header := false
	sc := bufio.NewScanner(bytes.NewReader(tmpl))
	for sc.Scan() {
		m := assignment.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		if _, ok := values[m[1]]; ok {
			continue
		}
		if !header {
			fmt.Fprintf(&out, "\n# Added by `make env` from .env.example on %s.\n", now.UTC().Format("2006-01-02"))
			header = true
		}
		v, err := resolve(m[1], m[2])
		if err != nil {
			return nil, nil, err
		}
		out.WriteString(m[1] + "=" + v + "\n")
	}
	return out.Bytes(), added, sc.Err()
}

// fill replaces placeholders in a template value.
func fill(raw string, values map[string]string, gen Generator) (string, error) {
	if m := bcryptToken.FindStringSubmatch(raw); m != nil {
		password, ok := values[m[1]]
		if !ok || password == "" {
			return "", fmt.Errorf("%s must be defined (earlier in the file) before its hash", m[1])
		}
		h, err := gen.Bcrypt(password)
		if err != nil {
			return "", fmt.Errorf("hash %s: %w", m[1], err)
		}
		// Single quotes stop both sh and docker compose from treating the
		// "$" signs in a bcrypt hash as variable references.
		return "'" + h + "'", nil
	}
	for strings.Contains(raw, secretToken) {
		raw = strings.Replace(raw, secretToken, gen.Secret(), 1)
	}
	return raw, nil
}

// parseValues reads KEY=VALUE lines of an env file.
func parseValues(data []byte) map[string]string {
	values := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if m := assignment.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
			values[m[1]] = unquote(m[2])
		}
	}
	return values
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// writePrivate replaces path atomically with mode 0600: the file holds
// secrets, and a crash mid-write must not leave a truncated .env behind.
func writePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".env.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
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
