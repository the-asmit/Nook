package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// ProjectFile is the project configuration file `nook init` writes.
const ProjectFile = "nook.toml"

// maxProjectFileSize bounds how much of nook.toml is read.
const maxProjectFileSize = 64 << 10

// Project is the content of nook.toml.
type Project struct {
	// App is the app's slug (its name in URLs).
	App string `toml:"app"`
	// Workspace optionally pins the workspace the app belongs to.
	Workspace       string `toml:"workspace,omitempty"`
	Port            int32  `toml:"port"`
	HealthCheckPath string `toml:"health_check_path"`
	MemoryMB        int32  `toml:"memory_mb"`
	CPUMillicores   int32  `toml:"cpu_millicores"`
	// StartupTimeout is how many seconds a new version may take to answer
	// its health check (default 60; the server caps it).
	StartupTimeout int32 `toml:"startup_timeout,omitempty"`
	// ReadOnlyRootfs runs the container with a read-only root file system
	// (writable /tmp only).
	ReadOnlyRootfs bool `toml:"read_only_rootfs,omitempty"`
}

var slugRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// Validate checks the values with messages that name the offending key.
func (p *Project) Validate() error {
	var errs []error
	if !slugRE.MatchString(p.App) {
		errs = append(errs, fmt.Errorf("app = %q: must be 1 to 40 lower-case letters, digits or inner hyphens", p.App))
	}
	if p.Workspace != "" && !slugRE.MatchString(p.Workspace) {
		errs = append(errs, fmt.Errorf("workspace = %q: not a valid workspace slug", p.Workspace))
	}
	if p.Port < 1 || p.Port > 65535 {
		errs = append(errs, fmt.Errorf("port = %d: must be between 1 and 65535", p.Port))
	}
	if !strings.HasPrefix(p.HealthCheckPath, "/") || len(p.HealthCheckPath) > 200 || strings.ContainsAny(p.HealthCheckPath, " \t\r\n") {
		errs = append(errs, fmt.Errorf("health_check_path = %q: must start with / (at most 200 characters, no spaces)", p.HealthCheckPath))
	}
	if p.MemoryMB < 16 {
		errs = append(errs, fmt.Errorf("memory_mb = %d: must be at least 16", p.MemoryMB))
	}
	if p.CPUMillicores < 10 {
		errs = append(errs, fmt.Errorf("cpu_millicores = %d: must be at least 10 (1000 = one CPU)", p.CPUMillicores))
	}
	if p.StartupTimeout < 1 || p.StartupTimeout > 3600 {
		errs = append(errs, fmt.Errorf("startup_timeout = %d: must be between 1 and 3600 seconds", p.StartupTimeout))
	}
	return errors.Join(errs...)
}

// defaultProject is what `nook init` starts from.
func defaultProject(app string) Project {
	return Project{App: app, Port: 8080, HealthCheckPath: "/", MemoryMB: 256, CPUMillicores: 500, StartupTimeout: 60}
}

// errNoProject means the folder has no nook.toml.
var errNoProject = errors.New("no " + ProjectFile + " in this folder; run 'nook init' first")

// loadProject reads and validates dir/nook.toml. Unknown keys are errors,
// so a typo cannot silently fall back to a default.
func loadProject(dir string) (Project, error) {
	path := filepath.Join(dir, ProjectFile)
	data, err := os.ReadFile(path) //nolint:gosec // G304: the project folder the user runs the CLI in.
	if errors.Is(err, fs.ErrNotExist) {
		return Project{}, errNoProject
	}
	if err != nil {
		return Project{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxProjectFileSize {
		return Project{}, fmt.Errorf("%s is larger than %d bytes", path, maxProjectFileSize)
	}
	p := defaultProject("")
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			return Project{}, fmt.Errorf("%s: unknown setting: %s", path, strings.TrimSpace(strict.String()))
		}
		var de *toml.DecodeError
		if errors.As(err, &de) {
			row, col := de.Position()
			return Project{}, fmt.Errorf("%s:%d:%d: %s", path, row, col, de.Error())
		}
		return Project{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return Project{}, fmt.Errorf("%s:\n%w", path, err)
	}
	return p, nil
}

// writeProject writes dir/nook.toml with explanatory comments.
func writeProject(dir string, p *Project) error {
	if err := p.Validate(); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Nook project configuration. `nook deploy` reads it from this folder.\n")
	fmt.Fprintf(&b, "# The app's name in URLs (lower-case letters, digits, hyphens).\napp = %q\n", p.App)
	if p.Workspace != "" {
		fmt.Fprintf(&b, "# The workspace the app belongs to.\nworkspace = %q\n", p.Workspace)
	}
	fmt.Fprintf(&b, "# The port your app listens on inside its container.\nport = %d\n", p.Port)
	fmt.Fprintf(&b, "# Path that answers 2xx when the app is healthy.\nhealth_check_path = %q\n", p.HealthCheckPath)
	fmt.Fprintf(&b, "# Resource limits: memory in MB, CPU in millicores (1000 = one CPU).\nmemory_mb = %d\ncpu_millicores = %d\n", p.MemoryMB, p.CPUMillicores)
	fmt.Fprintf(&b, "# Seconds a new version may take to pass its health check before the\n# deploy fails (the previous version keeps serving).\nstartup_timeout = %d\n", p.StartupTimeout)
	if p.ReadOnlyRootfs {
		b.WriteString("# Run with a read-only root file system (only /tmp is writable).\nread_only_rootfs = true\n")
	}
	path := filepath.Join(dir, ProjectFile)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { //nolint:gosec // G306: project config holds no secrets and is meant to be committed.
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// slugFromDir derives an app slug from a folder name.
func slugFromDir(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "app"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(filepath.Base(abs)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		return "app"
	}
	return s
}
