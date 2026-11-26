package agent

import (
	"strings"
	"testing"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

func validBuildCommand() *agentv1.BuildCommand {
	return &agentv1.BuildCommand{
		BuildId: "01a21756-2e93-7983-9533-63eabd671745", SourceSha256: strings.Repeat("ab", 32), SourceSize: 10,
		SourceUrl: "https://storage/x", Registry: "registry:5000", RegistryToken: "t",
		Repository: "ws1/app1", Tag: "b-1", CacheRepository: "ws1/app1/cache",
	}
}

// TestBuildCacheFlags: builds import and export the app's own cache;
// a cache outside the app's repository is refused; without one, no flags.
func TestBuildCacheFlags(t *testing.T) {
	cmd := validBuildCommand()
	if err := validateBuild(cmd); err != nil {
		t.Fatalf("valid command: %v", err)
	}
	args := strings.Join(cacheArgs(cmd), " ")
	for _, want := range []string{
		"--import-cache type=registry,ref=registry:5000/ws1/app1/cache:buildcache",
		"--export-cache type=registry,ref=registry:5000/ws1/app1/cache:buildcache,mode=max,image-manifest=true,oci-mediatypes=true,ignore-error=true",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("cache args lack %q: %s", want, args)
		}
	}
	for _, bad := range []string{"ws2/app2/cache", "ws1/app1", "ws1/app10/cache", "ws1/app1/../app2", "WS1/app1/cache"} {
		c := validBuildCommand()
		c.CacheRepository = bad
		if validateBuild(c) == nil {
			t.Errorf("cache repository %q accepted", bad)
		}
	}
	cmd.CacheRepository = ""
	if err := validateBuild(cmd); err != nil || len(cacheArgs(cmd)) != 0 {
		t.Fatalf("without a cache: %v %v", err, cacheArgs(cmd))
	}
	b := &builder{cfg: &Config{BuildImage: "img"}, nodeID: func() string { return "n" }}
	spec := b.containerSpec(validBuildCommand(), proxyConfig{})
	if !strings.Contains(strings.Join(spec.Config.Cmd, " "), "--export-cache") {
		t.Fatalf("the build container does not export the cache: %v", spec.Config.Cmd)
	}
}
