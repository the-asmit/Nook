package apps

import (
	"testing"
	"time"
	"uuid"

	"github.com/the-asmit/nook/internal/apperr"
)

func service() *Service {
	return &Service{cfg: Config{MaxAppMemoryMB: 1024, MaxAppCPUMillicores: 2000, MaxStartupTimeout: 5 * time.Minute,
		DefaultSleepAfter: 15 * time.Minute, MinSleepAfter: time.Minute, MaxSleepAfter: 24 * time.Hour}}
}

func TestNormalizeAppliesDefaults(t *testing.T) {
	spec, err := service().normalize(&Spec{Slug: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.sleepAfterSeconds == nil || *spec.sleepAfterSeconds != 900 {
		t.Fatalf("default sleep_after = %v, want 900 s", spec.sleepAfterSeconds)
	}
	spec.sleepAfterSeconds = nil
	want := Spec{Slug: "web", Name: "web", Port: DefaultPort, HealthCheckPath: "/", MemoryMB: DefaultMemoryMB,
		CPUMillicores: DefaultCPUMillicores, StartupTimeoutSeconds: 60}
	if spec != want {
		t.Fatalf("got %+v", spec)
	}
}

func TestSleepAfter(t *testing.T) {
	s := service()
	for in, want := range map[string]string{"": "15m", "1m": "1m", "90m": "1h30m", "24h": "24h", "never": "never", "2h0m": "2h"} {
		secs, err := s.parseSleepAfter(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := FormatSleepAfter(secs); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"30s", "25h", "1m30.5s", "soon", "-5m", "Never"} {
		if _, err := s.parseSleepAfter(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNormalizeRejectsInvalidSpecs(t *testing.T) {
	for name, spec := range map[string]Spec{
		"slug with space":  {Slug: "my app"},
		"slug too long":    {Slug: "a123456789a123456789a123456789a1234567891"},
		"slug edge hyphen": {Slug: "-web"},
		"port":             {Slug: "web", Port: 70000},
		"path":             {Slug: "web", HealthCheckPath: "healthz"},
		"path with space":  {Slug: "web", HealthCheckPath: "/a b"},
		"memory over max":  {Slug: "web", MemoryMB: 2048},
		"memory under min": {Slug: "web", MemoryMB: 8},
		"startup too long": {Slug: "web", StartupTimeoutSeconds: 301},
		"startup negative": {Slug: "web", StartupTimeoutSeconds: -1},
		"cpu over max":     {Slug: "web", CPUMillicores: 4000},
		"name too long":    {Slug: "web", Name: string(make([]rune, 101))},
	} {
		if _, err := service().normalize(&spec); err == nil {
			t.Errorf("%s: accepted", name)
		} else if e, ok := apperr.As(err); !ok || e.Kind != apperr.KindInvalid {
			t.Errorf("%s: not an invalid-input error: %v", name, err)
		}
	}
}

func TestRepositoryNameAndSourceKeys(t *testing.T) {
	ws, app := uuid.NewV7(), uuid.NewV7()
	if got := RepositoryName(ws, app); got != ws.String()+"/"+app.String() {
		t.Fatalf("repository %q", got)
	}
	a, err := sourceKey(ws, app, 7)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := sourceKey(ws, app, 7)
	if a == b || len(a) < len("sources/"+ws.String()+"/"+app.String()+"/7-")+32 {
		t.Fatalf("source keys not unguessable: %s %s", a, b)
	}
}
