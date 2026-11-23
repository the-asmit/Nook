package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

func validConfig(url string) Config {
	return Config{
		URL:               config.NewSecret(url),
		MaxConns:          10,
		MinConns:          1,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
		ConnectTimeout:    5 * time.Second,
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	c := validConfig("postgres://nook:pw@localhost:5432/nook?sslmode=disable")
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	c := validConfig("postgres://nook:pw@localhost:5432/nook")
	c.MaxConns = 0
	c.MinConns = 5
	c.ConnectTimeout = 0
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate() accepted invalid config")
	}
	for _, name := range []string{"NOOK_POSTGRES_MAX_CONNS", "NOOK_POSTGRES_MIN_CONNS", "NOOK_POSTGRES_CONNECT_TIMEOUT"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not mention %s: %v", name, err)
		}
	}
}

func TestValidateDoesNotLeakPasswordForBadURL(t *testing.T) {
	c := validConfig("postgres://nook:hunter2@localhost:notaport/nook")
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate() accepted a malformed URL")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaked the password: %v", err)
	}
	if !strings.Contains(err.Error(), "NOOK_POSTGRES_URL") {
		t.Fatalf("error does not name the variable: %v", err)
	}
}

func TestUsesTLS(t *testing.T) {
	cases := map[string]bool{
		"postgres://h/db?sslmode=disable":     false,
		"postgres://h/db?sslmode=allow":       false,
		"postgres://h/db?sslmode=prefer":      false,
		"postgres://h/db?sslmode=require":     true,
		"postgres://h/db?sslmode=verify-full": true,
		"host=h dbname=db sslmode=require":    true,
		"postgres://h:bad/db":                 false,
	}
	for url, want := range cases {
		c := validConfig(url)
		if got := c.UsesTLS(); got != want {
			t.Errorf("UsesTLS(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestPoolConfigAppliesSettings(t *testing.T) {
	c := validConfig("postgres://nook:pw@localhost:5432/nook?sslmode=disable&pool_max_conns=99")
	pc, err := c.poolConfig("nook-test")
	if err != nil {
		t.Fatal(err)
	}
	if pc.MaxConns != 10 || pc.MinConns != 1 {
		t.Errorf("conns = %d/%d, explicit settings must override the URL", pc.MaxConns, pc.MinConns)
	}
	if pc.ConnConfig.ConnectTimeout != 5*time.Second || pc.HealthCheckPeriod != 30*time.Second {
		t.Errorf("timeouts not applied: %+v", pc)
	}
	if got := pc.ConnConfig.RuntimeParams["application_name"]; got != "nook-test" {
		t.Errorf("application_name = %q", got)
	}

	c = validConfig("postgres://nook:pw@localhost:5432/nook?application_name=custom")
	pc, err = c.poolConfig("nook-test")
	if err != nil {
		t.Fatal(err)
	}
	if got := pc.ConnConfig.RuntimeParams["application_name"]; got != "custom" {
		t.Errorf("application_name from URL was overridden: %q", got)
	}

	c = validConfig("postgres://h:bad/db")
	if _, err := c.poolConfig("x"); err == nil {
		t.Error("poolConfig accepted malformed URL")
	}
}
