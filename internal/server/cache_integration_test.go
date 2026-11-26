//go:build integration

package server

import (
	"context"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/the-asmit/nook/internal/apps"
)

// cachedProject is a build whose RUN step is worth caching.
func cachedProject(t *testing.T, marker string) string {
	t.Helper()
	return project(t, map[string]string{
		"Dockerfile": "FROM __BASE__\nRUN echo expensive step && sleep 3 && echo done > /step.txt\nCOPY marker.txt /marker.txt\n",
		"marker.txt": marker + "\n",
	})
}

// runStepCached reports whether the build log shows the RUN step served
// from the cache rather than executed: an executed step prints its output
// ("#N 0.123 expensive step"); a hit from the registry cache only fetches
// the step's layer (or, from a local cache, prints "#N CACHED").
func runStepCached(t *testing.T, log string) bool {
	t.Helper()
	m := regexp.MustCompile(`(?m)^#(\d+) \[\d+/\d+\] RUN echo expensive step`).FindStringSubmatch(log)
	if m == nil {
		t.Fatalf("no RUN step in the build log:\n%s", log)
	}
	return !regexp.MustCompile(`(?m)^#` + m[1] + ` \d+\.\d+ expensive step$`).MatchString(log)
}

// TestBuildCacheIsPerApp: every build starts in a fresh BuildKit
// container, so a step can only come from the cache Nook keeps in the
// registry. The second build of an app reuses its RUN step; the same
// project in another app does not (caches never cross apps), and each
// app's cache lives in its own repository.
func TestBuildCacheIsPerApp(t *testing.T) {
	b := startBuildEnv(t, nil)
	b.createApp(b.alice, b.ws, "cached")
	b.createApp(b.alice, b.ws, "other")

	build := func(app, marker string) string {
		t.Helper()
		n := b.deploy(b.alice, b.ws, app, cachedProject(t, marker))
		if d := b.waitStatus(b.alice, b.ws, app, n, 3*time.Minute, "built", "failed"); d.Status != "built" {
			t.Fatalf("%s #%d: %s\n%s", app, n, d.FailureReason, b.buildLog(b.alice, b.ws, app, n))
		}
		return b.buildLog(b.alice, b.ws, app, n)
	}
	if runStepCached(t, build("cached", "one")) {
		t.Fatal("the first build of an app found a cache")
	}
	second := build("cached", "two")
	if !runStepCached(t, second) {
		t.Fatalf("the second build did not reuse the RUN step:\n%s", second)
	}
	if runStepCached(t, build("other", "one")) {
		t.Fatal("another app's build used this app's cache")
	}
	reg := registryClient(t)
	for _, app := range []string{"cached", "other"} {
		_, repo := b.appRepo(b.ws, app)
		tags, err := reg.Tags(context.Background(), repo+"/"+apps.CacheRepoSuffix)
		if err != nil || !slices.Equal(tags, []string{apps.CacheTag}) {
			t.Fatalf("%s's cache repository tags = %v, %v", app, tags, err)
		}
	}
}
