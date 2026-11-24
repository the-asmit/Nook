package device

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeClientName(t *testing.T) {
	if n, err := NormalizeClientName(""); err != nil || n != "nook CLI" {
		t.Fatalf("default = %q, %v", n, err)
	}
	if n, err := NormalizeClientName("  nook CLI on laptop "); err != nil || n != "nook CLI on laptop" {
		t.Fatalf("got %q, %v", n, err)
	}
	for _, bad := range []string{strings.Repeat("x", 101), "evil\nname", "bell\a"} {
		if _, err := NormalizeClientName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	ok := Config{CodeTTL: 10 * time.Minute, PollInterval: 5 * time.Second, TokenTTL: 90 * 24 * time.Hour}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := Config{CodeTTL: time.Second, PollInterval: time.Hour, TokenTTL: time.Minute}
	err := bad.Validate()
	for _, name := range []string{"NOOK_DEVICE_CODE_TTL", "NOOK_DEVICE_POLL_INTERVAL", "NOOK_CLI_TOKEN_TTL"} {
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("missing error for %s: %v", name, err)
		}
	}
}

func TestPollErrorsUseRFC8628Codes(t *testing.T) {
	for want, err := range map[string]error{
		"authorization_pending": ErrAuthorizationPending, "slow_down": ErrSlowDown,
		"access_denied": ErrAccessDenied, "expired_token": ErrExpiredToken, "invalid_grant": ErrInvalidGrant,
	} {
		if !strings.HasPrefix(err.Error(), want+":") {
			t.Errorf("%v does not carry code %s", err, want)
		}
	}
}
