package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretNeverPrintsPlaintext(t *testing.T) {
	s := NewSecret("hunter2")
	wrapper := struct{ URL Secret }{URL: s}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		for _, val := range []any{s, &s, wrapper} {
			if out := fmt.Sprintf(verb, val); strings.Contains(out, "hunter2") {
				t.Errorf("fmt %s of %T leaked the secret: %s", verb, val, out)
			}
		}
	}
	if s.String() != redacted {
		t.Errorf("String() = %q", s.String())
	}
}

func TestSecretIsRedactedInJSONAndLogs(t *testing.T) {
	s := NewSecret("hunter2")
	b, err := json.Marshal(struct{ URL Secret }{URL: s})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") || !strings.Contains(string(b), redacted) {
		t.Errorf("json = %s", b)
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "url", s)
	if strings.Contains(buf.String(), "hunter2") || !strings.Contains(buf.String(), redacted) {
		t.Errorf("log = %s", buf.String())
	}
}

func TestSecretRevealAndUnmarshal(t *testing.T) {
	var s Secret
	if !s.IsZero() {
		t.Fatal("zero Secret should report IsZero")
	}
	if err := s.UnmarshalText([]byte("value")); err != nil {
		t.Fatal(err)
	}
	if s.Reveal() != "value" || s.IsZero() {
		t.Fatalf("Reveal() = %q", s.Reveal())
	}
}
