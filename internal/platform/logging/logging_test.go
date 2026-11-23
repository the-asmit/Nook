package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"INFO", slog.LevelInfo},
		{"  warn  ", slog.LevelWarn}, // surrounding whitespace is tolerated
		{"error", slog.LevelError},
	}
	for _, c := range cases {
		got, err := ParseLevel(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "trace", "info+2", "warning"} {
		if _, err := ParseLevel(bad); err == nil {
			t.Errorf("ParseLevel(%q) accepted", bad)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	if err := (&Config{Level: "info"}).Validate(); err != nil {
		t.Errorf("valid level rejected: %v", err)
	}
	err := (&Config{Level: "loud"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "NOOK_LOG_LEVEL") {
		t.Errorf("invalid level error = %v", err)
	}
}

func decodeLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestNewWritesJSONWithAttrsAndLevel(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(&buf, Config{Level: "warn"}, slog.String("service", "test"))
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hidden")
	logger.Warn("shown", "k", "v")

	lines := decodeLines(t, &buf)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %s", len(lines), buf.String())
	}
	if lines[0]["msg"] != "shown" || lines[0]["service"] != "test" || lines[0]["k"] != "v" {
		t.Fatalf("unexpected record %v", lines[0])
	}
}

func TestNewRejectsInvalidLevel(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, Config{Level: "nope"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRequestIDFlowsFromContext(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(&buf, Config{Level: "info"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestID(context.Background(), "req-123")
	logger.With("a", 1).WithGroup("g").InfoContext(ctx, "with id")
	logger.InfoContext(context.Background(), "without id")

	lines := decodeLines(t, &buf)
	if len(lines) != 2 {
		t.Fatalf("got %d lines", len(lines))
	}
	group, ok := lines[0]["g"].(map[string]any)
	if !ok || group["request_id"] != "req-123" {
		t.Errorf("first line missing request_id: %v", lines[0])
	}
	if _, ok := lines[1]["request_id"]; ok {
		t.Errorf("second line should have no request_id: %v", lines[1])
	}
	if RequestIDFromContext(context.Background()) != "" {
		t.Error("empty context should have no request ID")
	}
}
