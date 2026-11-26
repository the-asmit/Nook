//go:build integration

package server

import (
	"strings"
	"testing"
)

// cliFor runs the real CLI as user u against the env.
func (b *buildEnv) cliFor(u user) *cliRunner {
	return &cliRunner{t: b.t, env: map[string]string{
		"NOOK_SERVER": b.base, "NOOK_TOKEN": u.token, "XDG_CONFIG_HOME": b.t.TempDir(), "NOOK_WORKSPACE": u.personal,
	}}
}

func TestBrokenDockerfileFailsWithReadableLog(t *testing.T) {
	b := startBuildEnv(t, nil)
	b.createApp(b.alice, b.ws, "broken")
	dir := project(t, map[string]string{
		"Dockerfile": "FROM __BASE__\nRUN echo compiling... && false\n",
		"nook.toml":  "app = \"broken\"\nport = 8080\nhealth_check_path = \"/\"\nmemory_mb = 64\ncpu_millicores = 100\n",
	})
	b.withBase(b.ws, "broken", dir)
	code, stdout, stderr := b.cliFor(b.alice).run("deploy", "--dir", dir)
	if code == 0 {
		t.Fatalf("a failing build exited 0\n%s", stdout)
	}
	if !strings.Contains(stdout, "compiling...") || !strings.Contains(stdout, "did not complete successfully") ||
		!strings.Contains(stdout, "Deployment #1 failed") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	d := b.deployment(b.alice, b.ws, "broken", 1)
	if d.Status != "failed" || len(d.Builds) != 1 || *d.Builds[0].Result != "failed" {
		t.Fatalf("user build errors must not be retried: %+v", d)
	}
}
