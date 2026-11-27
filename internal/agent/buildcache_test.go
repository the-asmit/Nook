package agent

import (
	"slices"
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

func TestBuildContainerConfinement(t *testing.T) {
	b := &builder{cfg: &Config{BuildImage: "img", BuildNetwork: "nook-builds"}, nodeID: func() string { return "n" }}
	hc := b.containerSpec(validBuildCommand(), proxyConfig{}).HostConfig
	if hc.Privileged || !slices.Equal(hc.CapDrop, []string{"ALL"}) || !slices.Equal(hc.CapAdd, []string{"SETUID", "SETGID"}) {
		t.Fatalf("privileges: privileged=%v drop=%v add=%v", hc.Privileged, hc.CapDrop, hc.CapAdd)
	}
	if len(hc.SecurityOpt) != 2 || hc.SecurityOpt[0] != "seccomp="+buildSeccompProfile || hc.SecurityOpt[1] != "apparmor=unconfined" {
		t.Fatalf("security options: %.80q", hc.SecurityOpt)
	}
	// Empty lists, not nil: nil would give Docker's default masks.
	if hc.MaskedPaths == nil || len(hc.MaskedPaths) != 0 || hc.ReadonlyPaths == nil || len(hc.ReadonlyPaths) != 0 {
		t.Fatalf("masked %v, read-only %v", hc.MaskedPaths, hc.ReadonlyPaths)
	}
	if len(hc.Binds) != 0 || len(hc.Mounts) != 0 {
		t.Fatalf("host mounts: %v %v", hc.Binds, hc.Mounts)
	}
}
