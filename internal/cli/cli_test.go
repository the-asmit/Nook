package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigRoundTripAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nook")
	cfg := Config{Server: "https://nook.example.com", Token: "nook_pat_x", Workspace: "team"}
	if err := saveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, configFileName))
		if err != nil {
			t.Fatal(err)
		}
		di, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
			t.Fatalf("file %v dir %v, want 0600/0700", fi.Mode().Perm(), di.Mode().Perm())
		}
	}
	got, err := loadConfig(dir)
	if err != nil || got != cfg {
		t.Fatalf("loadConfig = %+v, %v", got, err)
	}
}

func TestLoadConfigRefusesLooseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits do not apply on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, configFileName)
	if err := os.WriteFile(path, []byte(`{"token":"nook_pat_x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(dir); !errors.Is(err, ErrInsecureConfig) {
		t.Fatalf("err = %v, want ErrInsecureConfig", err)
	}
}

func TestLoadConfigMissingIsEmpty(t *testing.T) {
	cfg, err := loadConfig(filepath.Join(t.TempDir(), "absent"))
	if err != nil || cfg != (Config{}) {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

func TestConfigDir(t *testing.T) {
	xdg, home := t.TempDir(), t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": home}
	if d, _ := configDir(func(k string) string { return env[k] }); d != filepath.Join(xdg, "nook") {
		t.Errorf("XDG dir = %q", d)
	}
	delete(env, "XDG_CONFIG_HOME")
	if d, _ := configDir(func(k string) string { return env[k] }); d != filepath.Join(home, ".config", "nook") {
		t.Errorf("home dir = %q", d)
	}
}

func TestNormalizeServer(t *testing.T) {
	for _, ok := range []string{"https://nook.example.com", "https://nook.example.com/", "http://localhost:8080", "http://127.0.0.1:8080"} {
		if _, err := normalizeServer(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"nook.example.com", "http://nook.example.com", "ftp://x", "https://u:p@x", "https://x?y=1"} {
		if _, err := normalizeServer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func run(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	app := &App{Stdout: &out, Stderr: &errOut, Getenv: func(k string) string { return env[k] }}
	code := Execute(context.Background(), app, args)
	return code, out.String(), errOut.String()
}

func TestCommandsWithoutLoginFailClearly(t *testing.T) {
	env := map[string]string{"XDG_CONFIG_HOME": t.TempDir()}
	code, _, stderr := run(t, env, "whoami")
	if code != exitError || !strings.Contains(stderr, "not logged in") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	code, _, _ = run(t, env, "--output", "xml", "version")
	if code != exitUsage {
		t.Fatalf("bad --output: code %d", code)
	}
	code, _, _ = run(t, env, "workspace", "create")
	if code != exitError && code != exitUsage {
		t.Fatalf("missing argument: code %d", code)
	}
}

func TestAPIErrorsShowRequestID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"workspace not found","request_id":"req-42"}}`))
	}))
	defer srv.Close()
	env := map[string]string{"XDG_CONFIG_HOME": t.TempDir(), "NOOK_SERVER": srv.URL, "NOOK_TOKEN": "nook_pat_x"}
	code, _, stderr := run(t, env, "workspace", "use", "nope")
	if code != exitError || !strings.Contains(stderr, "workspace not found") || !strings.Contains(stderr, "req-42") {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
}

func TestVersionJSON(t *testing.T) {
	code, out, _ := run(t, map[string]string{}, "version", "-o", "json")
	if code != exitOK || !strings.Contains(out, `"version"`) {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestOpenBrowserRejectsNonWebURLs(t *testing.T) {
	if err := OpenBrowser("file:///etc/passwd"); err == nil {
		t.Fatal("file URL accepted")
	}
}
