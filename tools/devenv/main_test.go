package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const tmpl = `# comment mentioning __GENERATED_SECRET__ stays as is
A=fixed
PASSWORD=__GENERATED_SECRET__
PASSWORD_HASH=__BCRYPT:PASSWORD__
URL=postgres://u:${PASSWORD}@h/db
`

func counterGenerator() Generator {
	n := 0
	return Generator{
		Secret: func() string { n++; return fmt.Sprintf("secret%d", n) },
		Bcrypt: func(p string) (string, error) { return "$2a$04$hash-of-" + p, nil },
	}
}

var day = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)

func TestSyncCreatesFileFromTemplate(t *testing.T) {
	out, added, err := Sync([]byte(tmpl), nil, counterGenerator(), day)
	if err != nil {
		t.Fatal(err)
	}
	want := `# comment mentioning __GENERATED_SECRET__ stays as is
A=fixed
PASSWORD=secret1
PASSWORD_HASH='$2a$04$hash-of-secret1'
URL=postgres://u:${PASSWORD}@h/db
`
	if string(out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	if !slices.Equal(added, []string{"A", "PASSWORD", "PASSWORD_HASH", "URL"}) {
		t.Fatalf("added = %v", added)
	}
}

func TestSyncAppendsOnlyMissingAndKeepsExistingValues(t *testing.T) {
	existing := "A=changed\nPASSWORD=mine\n"
	out, added, err := Sync([]byte(tmpl), []byte(existing), counterGenerator(), day)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, existing) {
		t.Fatalf("existing content was modified:\n%s", s)
	}
	if !strings.Contains(s, "PASSWORD_HASH='$2a$04$hash-of-mine'") {
		t.Fatalf("hash must use the existing password:\n%s", s)
	}
	if !strings.Contains(s, "# Added by `make env` from .env.example on 2026-11-23.") {
		t.Fatal("missing header")
	}
	if !slices.Equal(added, []string{"PASSWORD_HASH", "URL"}) {
		t.Fatalf("added = %v", added)
	}

	again, added2, err := Sync([]byte(tmpl), out, counterGenerator(), day)
	if err != nil || len(added2) != 0 || string(again) != s {
		t.Fatalf("second sync should be a no-op: added=%v err=%v", added2, err)
	}
}

func TestSyncFailsWhenHashSourceMissing(t *testing.T) {
	if _, _, err := Sync([]byte("H=__BCRYPT:NOPE__\n"), nil, counterGenerator(), day); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRunWritesPrivateFileWithRealBcrypt(t *testing.T) {
	dir := t.TempDir()
	ex := filepath.Join(dir, "example")
	out := filepath.Join(dir, "env")
	if err := os.WriteFile(ex, []byte(tmpl), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-example", ex, "-out", out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
	values := parseValues(mustRead(t, out))
	if err := bcrypt.CompareHashAndPassword([]byte(values["PASSWORD_HASH"]), []byte(values["PASSWORD"])); err != nil {
		t.Fatalf("hash does not match password: %v", err)
	}
	if len(values["PASSWORD"]) != 32 {
		t.Fatalf("generated secret %q is not 128-bit hex", values["PASSWORD"])
	}
	if code := run([]string{"-example", filepath.Join(dir, "missing"), "-out", out}); code != 1 {
		t.Fatalf("missing template: exit %d, want 1", code)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
