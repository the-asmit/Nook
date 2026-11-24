package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/the-asmit/nook/internal/platform/config"
)

func devEnviron() map[string]string {
	return map[string]string{
		"NOOK_ENV":                   "development",
		"NOOK_PUBLIC_URL":            "http://localhost:8080",
		"NOOK_POSTGRES_URL":          "postgres://nook:pw@127.0.0.1:5432/nook?sslmode=disable",
		"NOOK_REDIS_URL":             "redis://:pw@127.0.0.1:6379/0",
		"NOOK_OIDC_ISSUER_URL":       "http://localhost:5556/dex",
		"NOOK_OIDC_CLIENT_ID":        "nook-dev",
		"NOOK_OIDC_CLIENT_SECRET":    "client-secret",
		"NOOK_ALLOWED_EMAIL_DOMAINS": "nook.test",
	}
}

// prodEnviron is a production configuration with TLS everywhere.
func prodEnviron(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	return map[string]string{
		"NOOK_ENV":                    "production",
		"NOOK_PUBLIC_URL":             "https://nook.example.com",
		"NOOK_POSTGRES_URL":           "postgres://nook:pw@db.example.com:5432/nook?sslmode=verify-full",
		"NOOK_REDIS_URL":              "rediss://:pw@cache.example.com:6380/0",
		"NOOK_HTTP_TLS_CERT_PATH":     filepath.Join(dir, "cert.pem"),
		"NOOK_HTTP_TLS_KEY_PATH":      filepath.Join(dir, "key.pem"),
		"NOOK_OIDC_ISSUER_URL":        "https://accounts.google.com",
		"NOOK_OIDC_CLIENT_ID":         "client.apps.googleusercontent.com",
		"NOOK_OIDC_CLIENT_SECRET":     "client-secret",
		"NOOK_BOOTSTRAP_ADMIN_EMAILS": "admin@example.com",
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
	for _, want := range []string{"NOOK_HTTP_TLS_CERT_PATH", "sslmode=verify-full", "rediss://", "NOOK_PUBLIC_URL", "https:// NOOK_OIDC_ISSUER_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestProductionWithTLSIsAccepted(t *testing.T) {
	cfg, err := config.Load[Config](prodEnviron(t))
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(cfg.PlaintextWarnings()) != 0 {
		t.Fatalf("unexpected plaintext warnings %v", cfg.PlaintextWarnings())
	}
}

// TestPlaintextInternalException covers the NOOK_ALLOW_PLAINTEXT_INTERNAL
// rule for each kind of host, with and without the opt-in.
func TestPlaintextInternalException(t *testing.T) {
	cases := []struct {
		name       string
		pgURL      string
		redisURL   string
		internal   bool // all hosts qualify for the exception
		wantWarned []string
	}{
		{"loopback", "postgres://u:p@127.0.0.1:5432/db?sslmode=disable", "redis://:p@[::1]:6379/0", true, []string{"postgres (127.0.0.1)", "redis (::1)"}},
		{"unix socket", "postgres://u:p@/db?host=/var/run/postgresql&sslmode=disable", "unix:///run/redis/redis.sock", true, []string{"postgres (/var/run/postgresql)", "redis (/run/redis/redis.sock)"}},
		{"rfc1918", "postgres://u:p@10.1.2.3:5432/db?sslmode=disable", "redis://:p@192.168.1.20:6379/0", true, []string{"postgres (10.1.2.3)", "redis (192.168.1.20)"}},
		{"docker service names", "postgres://u:p@postgres:5432/db?sslmode=disable", "redis://:p@redis:6379/0", true, []string{"postgres (postgres)", "redis (redis)"}},
		{"public host", "postgres://u:p@db.example.com:5432/db?sslmode=disable", "redis://:p@8.8.8.8:6379/0", false, nil},
		{"mixed fallback hosts", "postgres://u:p@10.0.0.1,db.example.com/db?sslmode=disable", "rediss://:p@cache.example.com:6380/0", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := prodEnviron(t)
			env["NOOK_POSTGRES_URL"] = tc.pgURL
			env["NOOK_REDIS_URL"] = tc.redisURL

			_, err := config.Load[Config](env)
			if err == nil {
				t.Fatal("plaintext accepted without the opt-in")
			}
			if hint := strings.Contains(err.Error(), "NOOK_ALLOW_PLAINTEXT_INTERNAL"); hint != tc.internal {
				t.Errorf("opt-in hint shown = %v, want %v: %v", hint, tc.internal, err)
			}

			env["NOOK_ALLOW_PLAINTEXT_INTERNAL"] = "true"
			cfg, err := config.Load[Config](env)
			if tc.internal {
				if err != nil {
					t.Fatalf("internal hosts rejected despite opt-in: %v", err)
				}
				if got := cfg.PlaintextWarnings(); !slices.Equal(got, tc.wantWarned) {
					t.Errorf("warnings = %v, want %v", got, tc.wantWarned)
				}
			} else if err == nil {
				t.Fatal("non-internal host accepted with plaintext")
			}
		})
	}
}

func TestOptInDoesNotRelaxOtherTLSRules(t *testing.T) {
	env := prodEnviron(t)
	env["NOOK_ALLOW_PLAINTEXT_INTERNAL"] = "true"
	env["NOOK_OIDC_ISSUER_URL"] = "http://dex:5556/dex"
	delete(env, "NOOK_HTTP_TLS_CERT_PATH")
	delete(env, "NOOK_HTTP_TLS_KEY_PATH")
	_, err := config.Load[Config](env)
	if err == nil || !strings.Contains(err.Error(), "NOOK_OIDC_ISSUER_URL") || !strings.Contains(err.Error(), "NOOK_HTTP_TLS_CERT_PATH") {
		t.Fatalf("Load() = %v, want issuer and HTTP TLS errors", err)
	}
}

func TestPublicURLRules(t *testing.T) {
	cases := map[string]bool{
		"http://localhost:8080":         true,
		"http://127.0.0.1:8080/":        true,
		"https://nook.example.com":      true,
		"http://nook.example.com":       false, // plain HTTP only for loopback
		"https://nook.example.com/sub":  false,
		"https://u:p@nook.example.com":  false,
		"https://nook.example.com/?a=1": false,
		"ftp://nook.example.com":        false,
		"localhost:8080":                false,
	}
	for url, ok := range cases {
		env := devEnviron()
		env["NOOK_PUBLIC_URL"] = url
		_, err := config.Load[Config](env)
		if (err == nil) != ok {
			t.Errorf("NOOK_PUBLIC_URL=%q: err = %v, want ok=%v", url, err, ok)
		}
	}
	env := devEnviron()
	env["NOOK_OIDC_REDIRECT_URL"] = "http://evil.example/auth/callback"
	if _, err := config.Load[Config](env); err == nil {
		t.Error("redirect URL on another origin accepted")
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

// TestExampleEnvFileIsValid loads .env.example exactly the way the Makefile
// does (sourced by sh) and checks that nook-server accepts the result.
func TestExampleEnvFileIsValid(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "sh", "-c", "set -a; . ../../.env.example; set +a; env")
	// Start from an empty environment so the host's variables cannot mask
	// a missing or broken entry.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf(".env.example is not valid sh: %v", err)
	}
	env := map[string]string{}
	for line := range strings.SplitSeq(string(out), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.HasPrefix(k, "NOOK_") {
			env[k] = v
		}
	}
	if _, err := config.Load[Config](env); err != nil {
		t.Fatalf(".env.example does not load: %v", err)
	}
}
