package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeToml(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ProjectFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadProject(t *testing.T) {
	dir := writeToml(t, "app = \"web\"\nport = 3000\n")
	p, err := loadProject(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.App != "web" || p.Port != 3000 || p.HealthCheckPath != "/" || p.MemoryMB != 256 || p.CPUMillicores != 500 {
		t.Fatalf("defaults not applied: %+v", p)
	}
	if _, err := loadProject(t.TempDir()); !errors.Is(err, errNoProject) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestLoadProjectErrorsAreClear(t *testing.T) {
	for content, want := range map[string]string{
		"app = \"web\"\nprot = 3000\n":                     "unknown setting",
		"app = \"Web App\"\n":                              `app = "Web App"`,
		"app = \"web\"\nport = 70000\n":                    "port = 70000",
		"app = \"web\"\nhealth_check_path = \"healthz\"\n": "health_check_path",
		"app = \"web\"\nmemory_mb = 8\n":                   "memory_mb = 8",
		"app = \"web\"\ncpu_millicores = 1\n":              "cpu_millicores = 1",
		"app = \"web\"\nport = \"eighty\"\n":               ProjectFile,
		"app = \"web\"\nworkspace = \"NOT A SLUG\"\n":      "workspace",
	} {
		_, err := loadProject(writeToml(t, content))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v does not mention %q", content, err, want)
		}
	}
}

func TestWriteProjectRoundTrips(t *testing.T) {
	dir := t.TempDir()
	p := defaultProject("hello")
	p.Workspace, p.Port = "acme", 9000
	if err := writeProject(dir, &p); err != nil {
		t.Fatal(err)
	}
	got, err := loadProject(dir)
	if err != nil || got != p {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	bad := defaultProject("Bad")
	if writeProject(dir, &bad) == nil {
		t.Fatal("invalid project written")
	}
}

func TestSlugFromDir(t *testing.T) {
	for in, want := range map[string]string{
		"/tmp/My Cool_App": "my-cool-app", "/tmp/---": "app", "/x/" + strings.Repeat("a", 60): strings.Repeat("a", 40),
	} {
		if got := slugFromDir(in); got != want {
			t.Errorf("slugFromDir(%q) = %q, want %q", in, got, want)
		}
	}
}
