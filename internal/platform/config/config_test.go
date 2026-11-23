package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testConfig struct {
	Name    string        `env:"NOOK_NAME,required,notEmpty"`
	Timeout time.Duration `env:"NOOK_TIMEOUT" envDefault:"5s"`
	Token   Secret        `env:"NOOK_TOKEN"`
}

func (c *testConfig) Validate() error {
	return CheckDuration("NOOK_TIMEOUT", c.Timeout, time.Second, time.Minute)
}

func TestLoadParsesDefaultsAndValues(t *testing.T) {
	cfg, err := Load[testConfig](map[string]string{"NOOK_NAME": "nook", "NOOK_TOKEN": "s3cret"})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Name != "nook" || cfg.Timeout != 5*time.Second || cfg.Token.Reveal() != "s3cret" {
		t.Fatalf("Load() = %+v", cfg)
	}
}

func TestLoadReportsMissingRequiredVariable(t *testing.T) {
	_, err := Load[testConfig](map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "NOOK_NAME") {
		t.Fatalf("Load() error = %v, want mention of NOOK_NAME", err)
	}
}

func TestLoadReportsUnparsableValue(t *testing.T) {
	_, err := Load[testConfig](map[string]string{"NOOK_NAME": "x", "NOOK_TIMEOUT": "soon"})
	if err == nil || !strings.Contains(err.Error(), "Timeout") {
		t.Fatalf("Load() error = %v, want a parse error for Timeout", err)
	}
}

func TestLoadRunsValidation(t *testing.T) {
	_, err := Load[testConfig](map[string]string{"NOOK_NAME": "x", "NOOK_TIMEOUT": "2h"})
	if err == nil || !strings.Contains(err.Error(), "NOOK_TIMEOUT: must be between") {
		t.Fatalf("Load() error = %v, want validation error", err)
	}
}

func TestLoadReadsFileVariables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load[testConfig](map[string]string{"NOOK_NAME": "x", "NOOK_TOKEN_FILE": path})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Token.Reveal(); got != "from-file" {
		t.Fatalf("Token = %q, want trailing newline trimmed %q", got, "from-file")
	}
}

func TestResolveFileVariablesErrors(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		environ map[string]string
		want    string
	}{
		{"both set", map[string]string{"NOOK_TOKEN": "a", "NOOK_TOKEN_FILE": big}, "both set"},
		{"missing file", map[string]string{"NOOK_TOKEN_FILE": filepath.Join(dir, "absent")}, "open file"},
		{"empty path", map[string]string{"NOOK_TOKEN_FILE": ""}, "path is empty"},
		{"too large", map[string]string{"NOOK_TOKEN_FILE": big}, "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveFileVariables(tt.environ)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestResolveFileVariablesIgnoresForeignAndDegenerateKeys(t *testing.T) {
	environ := map[string]string{"OTHER_FILE": "/nonexistent", "NOOK__FILE": "/nonexistent", "NOOK_A": "b"}
	out, err := resolveFileVariables(environ)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if out["OTHER_FILE"] != "/nonexistent" || out["NOOK_A"] != "b" {
		t.Fatalf("unexpected output %v", out)
	}
}

func TestProblemsFlattensJoinedErrors(t *testing.T) {
	err := errors.Join(errors.New("a"), errors.Join(errors.New("b"), errors.New("c")))
	got := Problems(errors.Join(err))
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("Problems() = %v, want [a b c]", got)
	}
	if Problems(nil) != nil {
		t.Fatal("Problems(nil) should be nil")
	}
	single := Problems(errors.New("only"))
	if len(single) != 1 || single[0] != "only" {
		t.Fatalf("Problems(single) = %v", single)
	}
}

func TestProblemsFromLoad(t *testing.T) {
	_, err := Load[testConfig](map[string]string{"NOOK_TIMEOUT": "soon"})
	if got := Problems(err); len(got) < 2 {
		t.Fatalf("Problems() = %v, want one entry per problem", got)
	}
}

func TestOSEnviron(t *testing.T) {
	t.Setenv("NOOK_OS_ENVIRON_TEST", "value")
	if got := OSEnviron()["NOOK_OS_ENVIRON_TEST"]; got != "value" {
		t.Fatalf("OSEnviron() missing variable, got %q", got)
	}
}
