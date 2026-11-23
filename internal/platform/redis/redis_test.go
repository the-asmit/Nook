package redis

import (
	"strings"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

func validConfig(url string) Config {
	return Config{
		URL:          config.NewSecret(url),
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
	}
}

func TestValidate(t *testing.T) {
	c := validConfig("redis://:pw@localhost:6379/0")
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	c.PoolSize = 0
	c.ReadTimeout = 0
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "NOOK_REDIS_POOL_SIZE") || !strings.Contains(err.Error(), "NOOK_REDIS_READ_TIMEOUT") {
		t.Fatalf("Validate() = %v, want pool size and read timeout errors", err)
	}
}

func TestValidateDoesNotLeakPassword(t *testing.T) {
	for _, url := range []string{
		"redis://:hunter2@[::1:6379/0",
		"http://:hunter2@localhost:6379",
		"redis://:hunter2@localhost:6379/notanumber",
	} {
		c := validConfig(url)
		err := c.Validate()
		if err == nil {
			t.Fatalf("Validate(%q) accepted a bad URL", url)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("Validate(%q) leaked the password: %v", url, err)
		}
	}
}

func TestUsesTLS(t *testing.T) {
	cases := map[string]bool{
		"redis://localhost:6379":  false,
		"rediss://localhost:6380": true,
		"bogus://localhost":       false,
	}
	for url, want := range cases {
		c := validConfig(url)
		if got := c.UsesTLS(); got != want {
			t.Errorf("UsesTLS(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestNewClientAppliesSettings(t *testing.T) {
	c := validConfig("redis://:pw@localhost:6379/2")
	c.PoolSize = 7
	client, err := NewClient(&c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	opts := client.Options()
	if opts.PoolSize != 7 || opts.DB != 2 || opts.Password != "pw" {
		t.Errorf("options = pool %d db %d", opts.PoolSize, opts.DB)
	}
	if opts.DialTimeout != 5*time.Second || opts.ReadTimeout != 3*time.Second || opts.WriteTimeout != 3*time.Second {
		t.Errorf("timeouts not applied")
	}
	if !opts.ContextTimeoutEnabled {
		t.Error("ContextTimeoutEnabled must be on")
	}

	if _, err := NewClient(new(validConfig("bogus://x"))); err == nil {
		t.Error("NewClient accepted a bad URL")
	}
}
