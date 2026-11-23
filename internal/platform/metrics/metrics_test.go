package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/the-asmit/nook/internal/version"
)

func TestRegistryServesBuildInfoAndRuntimeMetrics(t *testing.T) {
	info := version.Info{Version: "v9.9.9", Commit: "abc", BuildDate: "2026-01-01T00:00:00Z", GoVersion: "go1.27.4"}
	reg, err := NewRegistry("nook-test", info)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	Handler(reg).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`nook_build_info{build_date="2026-01-01T00:00:00Z",commit="abc",go_version="go1.27.4",service="nook-test",version="v9.9.9"} 1`,
		"go_goroutines",
		"process_cpu_seconds_total",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}
