package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/the-asmit/nook/internal/platform/config"
)

func devEnviron() map[string]string {
	return map[string]string{
		"NOOK_ENV":          "development",
		"NOOK_POSTGRES_URL": "postgres://nook:pw@127.0.0.1:5432/nook?sslmode=disable",
		"NOOK_REDIS_URL":    "redis://:pw@127.0.0.1:6379/0",
	}
}

func TestLoadDevelopmentDefaults(t *testing.T) {
	cfg, err := config.Load[Config](devEnviron())
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if cfg.HTTP.Addr != ":8080" || cfg.Log.Level != "info" || cfg.Postgres.MaxConns != 10 || cfg.Redis.PoolSize != 10 {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestLoadRequiresCoreVariables(t *testing.T) {
	_, err := config.Load[Config](map[string]string{})
	if err == nil {
		t.Fatal("Load() accepted an empty environment")
	}
	for _, name := range []string{"NOOK_ENV", "NOOK_POSTGRES_URL", "NOOK_REDIS_URL"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not mention %s: %v", name, err)
		}
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	env := devEnviron()
	env["NOOK_ENV"] = "prod"
	env["NOOK_LOG_LEVEL"] = "loud"
	env["NOOK_HTTP_ADDR"] = "nope"
	env["NOOK_READINESS_TIMEOUT"] = "30s"
	_, err := config.Load[Config](env)
	if err == nil {
		t.Fatal("Load() accepted invalid values")
	}
	problems := config.Problems(err)
	if len(problems) < 4 {
		t.Fatalf("want at least 4 separate problems, got %d: %v", len(problems), problems)
	}
	for _, want := range []string{"NOOK_ENV", "NOOK_LOG_LEVEL", "NOOK_HTTP_ADDR", "NOOK_READINESS_TIMEOUT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s", want)
		}
	}
}

func TestProductionRequiresTLSEverywhere(t *testing.T) {
	env := devEnviron()
	env["NOOK_ENV"] = "production"
	_, err := config.Load[Config](env)
	if err == nil {
		t.Fatal("production without TLS was accepted")
	}
	for _, want := range []string{"NOOK_HTTP_TLS_CERT_PATH", "sslmode=verify-full", "rediss://"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestProductionWithTLSIsAccepted(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"NOOK_ENV":                "production",
		"NOOK_POSTGRES_URL":       "postgres://nook:pw@db.internal:5432/nook?sslmode=verify-full",
		"NOOK_REDIS_URL":          "rediss://:pw@cache.internal:6380/0",
		"NOOK_HTTP_TLS_CERT_PATH": filepath.Join(dir, "cert.pem"),
		"NOOK_HTTP_TLS_KEY_PATH":  filepath.Join(dir, "key.pem"),
	}
	if _, err := config.Load[Config](env); err != nil {
		t.Fatalf("Load() = %v", err)
	}
}

func TestSecretsCanComeFromFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pg-url")
	if err := os.WriteFile(path, []byte("postgres://nook:filepw@127.0.0.1:5432/nook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := devEnviron()
	delete(env, "NOOK_POSTGRES_URL")
	env["NOOK_POSTGRES_URL_FILE"] = path
	cfg, err := config.Load[Config](env)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if !strings.Contains(cfg.Postgres.URL.Reveal(), "filepw") {
		t.Fatal("URL was not read from the file")
	}
}

// .env.example lists optional variables with empty values; they must
// behave exactly like unset variables.
func TestEmptyOptionalVariablesActAsUnset(t *testing.T) {
	env := devEnviron()
	env["NOOK_HTTP_TRUSTED_PROXIES"] = ""
	env["NOOK_HTTP_TLS_CERT_PATH"] = ""
	env["NOOK_HTTP_TLS_KEY_PATH"] = ""
	env["NOOK_LOG_LEVEL"] = ""
	cfg, err := config.Load[Config](env)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(cfg.HTTP.TrustedProxies) != 0 || cfg.HTTP.TLSEnabled() || cfg.Log.Level != "info" {
		t.Fatalf("empty values not treated as unset: proxies=%q tls=%v level=%q",
			cfg.HTTP.TrustedProxies, cfg.HTTP.TLSEnabled(), cfg.Log.Level)
	}
}

func TestExampleEnvFileIsValid(t *testing.T) {
	data, err := os.ReadFile("../../.env.example")
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed line %q", line)
		}
		env[k] = os.Expand(strings.ReplaceAll(v, "__GENERATED_SECRET__", "s3cret"), func(name string) string { return env[name] })
	}
	if _, err := config.Load[Config](env); err != nil {
		t.Fatalf(".env.example does not load: %v", err)
	}
}
