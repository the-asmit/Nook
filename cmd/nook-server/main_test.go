package main

import (
	"bytes"
	"encoding/json"
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
