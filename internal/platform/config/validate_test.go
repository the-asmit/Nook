package config

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEnvironment(t *testing.T) {
	for _, e := range []Environment{Development, Staging, Production} {
		if err := e.Validate(); err != nil {
			t.Errorf("%s.Validate() = %v", e, err)
		}
	}
	if err := Environment("prod").Validate(); err == nil {
		t.Error("unknown environment should be rejected")
	}
	if !Development.IsDevelopment() || Production.IsDevelopment() {
		t.Error("IsDevelopment mismatch")
	}
	if Development.RequiresTLS() || !Staging.RequiresTLS() || !Production.RequiresTLS() {
		t.Error("RequiresTLS mismatch")
	}
}

func TestCheckDuration(t *testing.T) {
	if err := CheckDuration("X", time.Second, time.Second, time.Minute); err != nil {
		t.Errorf("lower bound rejected: %v", err)
	}
	if err := CheckDuration("X", 0, time.Second, time.Minute); err == nil || !strings.HasPrefix(err.Error(), "X:") {
		t.Errorf("below range: %v", err)
	}
	if err := CheckDuration("X", time.Hour, time.Second, time.Minute); err == nil {
		t.Error("above range accepted")
	}
}

func TestCheckRange(t *testing.T) {
	if err := CheckRange("N", 5, 1, 10); err != nil {
		t.Errorf("in range rejected: %v", err)
	}
	if err := CheckRange("N", int64(11), 1, 10); err == nil || !strings.Contains(err.Error(), "N:") {
		t.Errorf("out of range: %v", err)
	}
}

func TestCheckListenAddr(t *testing.T) {
	for _, ok := range []string{":8080", "127.0.0.1:0", "[::1]:443", "localhost:65535"} {
		if err := CheckListenAddr("A", ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"8080", "host:", "host:http", ":65536", ":-1", ""} {
		if err := CheckListenAddr("A", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRedactURLError(t *testing.T) {
	_, err := url.Parse("redis://user:hunter2@[::1:6379") //nolint:staticcheck // SA1007: deliberately invalid.
	if err == nil {
		t.Fatal("expected a parse error")
	}
	got := RedactURLError(err)
	if strings.Contains(got.Error(), "hunter2") {
		t.Fatalf("redacted error leaked password: %v", got)
	}

	_, err = url.Parse("redis://user:hun%zzter2@host:6379") //nolint:staticcheck // SA1007: deliberately invalid.
	if err == nil {
		t.Fatal("expected an escape error")
	}
	if got := RedactURLError(err).Error(); strings.Contains(got, "zz") {
		t.Fatalf("escape error leaked password bytes: %v", got)
	}

	plain := errors.New("other")
	if !errors.Is(RedactURLError(plain), plain) {
		t.Fatal("non-URL errors must pass through unchanged")
	}
}
