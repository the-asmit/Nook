package api

import (
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-asmit/nook/internal/auth"
	"github.com/the-asmit/nook/internal/platform/httpserver"
)

type openAPISpec struct {
	OpenAPI string                    `yaml:"openapi"`
	Paths   map[string]map[string]any `yaml:"paths"`
}

// specRoutes returns "METHOD /path" for every operation in the spec.
func specRoutes(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec openAPISpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("api/openapi.yaml is not valid YAML: %v", err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.1.") {
		t.Fatalf("openapi = %q, want 3.1.x", spec.OpenAPI)
	}
	var routes []string
	for path, item := range spec.Paths {
		for method, raw := range item {
			if method == "parameters" {
				continue
			}
			op, ok := raw.(map[string]any)
			if !ok {
				t.Errorf("%s %s is not an operation object", method, path)
				continue
			}
			if _, ok := op["responses"]; !ok {
				t.Errorf("%s %s has no responses", method, path)
			}
			routes = append(routes, strings.ToUpper(method)+" "+path)
		}
	}
	slices.Sort(routes)
	return routes
}

var ginParam = regexp.MustCompile(`:([a-z_]+)`)

// apiRoutes returns "METHOD /path" for every JSON route the server
// registers, with Gin's :param written the OpenAPI way as {param}.
func apiRoutes(t *testing.T) []string {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r, err := NewRouter(&Deps{
		Logger: logger, Registry: prometheus.NewRegistry(),
		HTTP: httpserver.Config{MaxBodyBytes: 1 << 20, RequestTimeout: time.Second}, ReadinessTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	site := auth.NewSite(&url.URL{Scheme: "http", Host: "localhost:8080"})
	RegisterV1(r, &V1Deps{Logger: logger, Auth: auth.NewAuthenticator(nil, nil, site, logger)})

	var routes []string
	for _, rt := range r.Routes() {
		routes = append(routes, rt.Method+" "+ginParam.ReplaceAllString(rt.Path, "{$1}"))
	}
	slices.Sort(routes)
	return routes
}

// TestOpenAPISpecMatchesRoutes fails when a route is added without being
// documented, or the spec documents a route that does not exist.
func TestOpenAPISpecMatchesRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	spec, routes := specRoutes(t), apiRoutes(t)
	for _, r := range routes {
		if !slices.Contains(spec, r) {
			t.Errorf("route %s is not documented in api/openapi.yaml", r)
		}
	}
	for _, s := range spec {
		if !slices.Contains(routes, s) {
			t.Errorf("api/openapi.yaml documents %s, which the server does not register", s)
		}
	}
	if len(routes) < 20 {
		t.Fatalf("only %d routes found; route discovery is broken", len(routes))
	}
}
