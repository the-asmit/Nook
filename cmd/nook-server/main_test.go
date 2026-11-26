package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--version"}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, "nook-server ") || !strings.Contains(out, "commit ") || !strings.Contains(out, "built ") {
		t.Fatalf("unexpected version output %q", out)
	}
}

func TestMissingRequiredVariablesAreReported(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, map[string]string{}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	for _, name := range []string{"NOOK_ENV", "NOOK_POSTGRES_URL", "NOOK_REDIS_URL"} {
		if !strings.Contains(stderr.String(), name) {
			t.Errorf("stderr does not mention %s: %s", name, stderr.String())
		}
	}
}

func TestUnknownFlagIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--bogus"}, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestInvalidConfigFailsFastWithStructuredProblems(t *testing.T) {
	var stdout, stderr bytes.Buffer
	environ := map[string]string{
		"NOOK_ENV":          "development",
		"NOOK_LOG_LEVEL":    "loud",
		"NOOK_POSTGRES_URL": "postgres://nook:pw@127.0.0.1:5432/nook",
		"NOOK_REDIS_URL":    "redis://127.0.0.1:6379/0",
		"NOOK_HTTP_ADDR":    "not-an-address",
		// Valid values for the other required settings, so that exactly the
		// two problems above are reported.
		"NOOK_PUBLIC_URL":            "http://localhost:8080",
		"NOOK_OIDC_ISSUER_URL":       "http://localhost:5556/dex",
		"NOOK_OIDC_CLIENT_ID":        "nook-dev",
		"NOOK_OIDC_CLIENT_SECRET":    "secret",
		"NOOK_ALLOWED_EMAIL_DOMAINS": "nook.test",
		"NOOK_S3_ENDPOINT":           "http://localhost:9000",
		"NOOK_S3_ACCESS_KEY_ID":      "nook",
		"NOOK_S3_SECRET_ACCESS_KEY":  "storage-secret",
		"NOOK_REGISTRY_ADDR":         "registry:5000",
		"NOOK_REGISTRY_GC_SECRET":    "0123456789abcdef",
		"NOOK_SECRETS_KEY":           "1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"NOOK_APPS_BASE_URL":         "http://apps.localhost:8090",
		"NOOK_GATEWAY_SECRET":        "gateway-secret-0123456789abcdef0123",
	}
	if code := run(nil, environ, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	var entry struct {
		Msg      string   `json:"msg"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal(stderr.Bytes(), &entry); err != nil {
		t.Fatalf("stderr is not a JSON log line: %q", stderr.String())
	}
	joined := strings.Join(entry.Problems, "\n")
	if entry.Msg != "invalid configuration" || len(entry.Problems) != 2 ||
		!strings.Contains(joined, "NOOK_HTTP_ADDR") || !strings.Contains(joined, "NOOK_LOG_LEVEL") {
		t.Fatalf("unexpected entry %+v", entry)
	}
}

func TestRegistryCert(t *testing.T) {
	dir := t.TempDir()
	environ := map[string]string{"NOOK_PKI_CA_PATH": filepath.Join(dir, "ca.pem")}
	out := filepath.Join(dir, "registry")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"registry-cert", "--out", out, "--names", "registry,127.0.0.1"}, environ, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for name, mode := range map[string]os.FileMode{"tls.crt": 0o644, "tls.key": 0o600, "ca.crt": 0o644} {
		info, err := os.Stat(filepath.Join(out, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	first, _ := os.ReadFile(filepath.Join(out, "tls.crt"))
	stdout.Reset()
	if code := run([]string{"registry-cert", "--out", out, "--names", "registry"}, environ, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "keeping it") {
		t.Fatalf("second run: %d %s", code, stdout.String())
	}
	if again, _ := os.ReadFile(filepath.Join(out, "tls.crt")); !bytes.Equal(first, again) {
		t.Fatal("a valid certificate was replaced")
	}
	if code := run([]string{"registry-cert", "--out", out}, environ, &stdout, &stderr); code != 2 {
		t.Fatalf("missing --names: exit %d", code)
	}
}
