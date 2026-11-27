//go:build integration

package testinfra

import (
	"fmt"
	"testing"

	tclog "github.com/testcontainers/testcontainers-go/log"
)

func TestPlainTextRemovesEmojis(t *testing.T) {
	for in, want := range map[string]string{
		"🐳 Creating container for image registry:3.1.2": "Creating container for image registry:3.1.2",
		"✍🏼 Replacing image with x":                     "Replacing image with x",
		"⏳ Waiting for container id 1a2b":               "Waiting for container id 1a2b",
		"✅ Container started: 1a2b":                     "Container started: 1a2b",
		"🔥 Reaper obtained from Docker":                 "Reaper obtained from Docker",
		"failed to start container: café ^ `x` ü":       "failed to start container: café ^ `x` ü",
	} {
		if got := plainText(in); got != want {
			t.Errorf("plainText(%q) = %q, want %q", in, got, want)
		}
	}
}

type recordingLogger struct{ lines []string }

func (r *recordingLogger) Printf(format string, v ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, v...))
}

func TestTestcontainersLoggerIsPlain(t *testing.T) {
	if _, ok := tclog.Default().(plainLogger); !ok {
		t.Fatalf("testcontainers' default logger is %T, want plainLogger", tclog.Default())
	}
	rec := &recordingLogger{}
	plainLogger{next: rec}.Printf("🐳 Starting container: %s", "1a2b")
	if len(rec.lines) != 1 || rec.lines[0] != "Starting container: 1a2b" {
		t.Fatalf("logged %q", rec.lines)
	}
}
