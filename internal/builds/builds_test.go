package builds

import (
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/store"
)

func TestConfigDefaultsAndBounds(t *testing.T) {
	c, err := config.Load[Config](map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Timeout != 15*time.Minute || c.ImageRetention != 10 || c.MaxAttempts != 3 {
		t.Fatalf("defaults %+v", c)
	}
	c.MaxAttempts = 0
	if c.Validate() == nil {
		t.Fatal("zero attempts accepted")
	}
}

func TestSanitize(t *testing.T) {
	in := "bad\x00line\twith\ncontrols " + strings.Repeat("x", 600) + "\xff"
	out := sanitize(in)
	if len(out) > maxMessageLength || strings.ContainsAny(out, "\x00\n\t") {
		t.Fatalf("sanitize: %q", out)
	}
	if sanitize("  ") != "" || orDefault("", "d") != "d" || orDefault("m", "d") != "m" {
		t.Fatal("helpers")
	}
}

func TestTerminal(t *testing.T) {
	for s, want := range map[store.DeploymentStatus]bool{
		store.DeploymentStatusBuilt: true, store.DeploymentStatusFailed: true, store.DeploymentStatusCancelled: true,
		store.DeploymentStatusQueued: false, store.DeploymentStatusBuilding: false, store.DeploymentStatusUploading: false,
	} {
		if Terminal(s) != want {
			t.Errorf("Terminal(%s) != %v", s, want)
		}
	}
}

func TestParseRepository(t *testing.T) {
	ws, app := uuid.NewV7(), uuid.NewV7()
	gotWS, gotApp, ok := parseRepository(ws.String() + "/" + app.String())
	if !ok || gotWS != ws || gotApp != app {
		t.Fatal("valid repository not parsed")
	}
	for _, bad := range []string{"library/alpine", "x", ws.String() + "/not-a-uuid"} {
		if _, _, ok := parseRepository(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestFailureReason(t *testing.T) {
	if failureReason(&store.Build{}) != "the build failed" || failureReason(&store.Build{Message: "m"}) != "m" {
		t.Fatal("failureReason")
	}
	if LogObjectKey(uuid.UUID{}, uuid.UUID{}, uuid.UUID{}, 2) == "" {
		t.Fatal("empty log key")
	}
}
