package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolveUsesInjectedValues(t *testing.T) {
	bi := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "fromvcs"}}}
	got := resolve("v1.2.3", "abc123", "2026-01-02T03:04:05Z", bi)
	want := Info{Version: "v1.2.3", Commit: "abc123", BuildDate: "2026-01-02T03:04:05Z", GoVersion: runtime.Version()}
	if got != want {
		t.Fatalf("resolve() = %+v, want %+v", got, want)
	}
}

func TestResolveFallsBackToVCSRevision(t *testing.T) {
	bi := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "fromvcs"}}}
	got := resolve("dev", "", "", bi)
	if got.Commit != "fromvcs" {
		t.Errorf("Commit = %q, want %q", got.Commit, "fromvcs")
	}
	if got.BuildDate != unknown {
		t.Errorf("BuildDate = %q, want %q", got.BuildDate, unknown)
	}
}

func TestResolveWithoutAnyInformation(t *testing.T) {
	got := resolve("", "", "", nil)
	if got.Version != "dev" || got.Commit != unknown || got.BuildDate != unknown {
		t.Fatalf("resolve() = %+v, want dev/unknown/unknown", got)
	}
}

func TestInfoString(t *testing.T) {
	s := Info{Version: "v1.0.0", Commit: "abc", BuildDate: "2026-01-01T00:00:00Z", GoVersion: "go1.27.4"}.String()
	for _, part := range []string{"v1.0.0", "commit abc", "built 2026-01-01T00:00:00Z", "go1.27.4"} {
		if !strings.Contains(s, part) {
			t.Errorf("String() = %q, missing %q", s, part)
		}
	}
}

func TestGetReturnsPopulatedInfo(t *testing.T) {
	info := Get()
	if info.Version == "" || info.Commit == "" || info.BuildDate == "" || info.GoVersion == "" {
		t.Fatalf("Get() returned empty fields: %+v", info)
	}
}
