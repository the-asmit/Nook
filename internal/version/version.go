// Package version exposes the build metadata of the running binary.
//
// The values are injected at link time, for example:
//
//	go build -ldflags "-X github.com/the-asmit/nook/internal/version.Version=v0.1.0"
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// These are variables rather than constants because the linker's -X flag can
// only overwrite package-level string variables.
var (
	// Version is the release version (usually `git describe` output).
	Version = "dev"
	// Commit is the full git commit hash the binary was built from.
	Commit = ""
	// BuildDate is the UTC time the binary was built, in RFC 3339 format.
	BuildDate = ""
)

const unknown = "unknown"

// Info describes the build of the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
}

// Get returns the build information of the running binary.
//
// When the commit was not injected through ldflags (for example under
// `go run`), it falls back to the VCS revision the Go toolchain embeds.
func Get() Info {
	bi, _ := debug.ReadBuildInfo()
	return resolve(Version, Commit, BuildDate, bi)
}

func resolve(ver, commit, buildDate string, bi *debug.BuildInfo) Info {
	if commit == "" && bi != nil {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				commit = s.Value
			}
		}
	}
	if ver == "" {
		ver = "dev"
	}
	if commit == "" {
		commit = unknown
	}
	if buildDate == "" {
		buildDate = unknown
	}
	return Info{Version: ver, Commit: commit, BuildDate: buildDate, GoVersion: runtime.Version()}
}

// String formats the build information for `--version` output.
func (i Info) String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s)", i.Version, i.Commit, i.BuildDate, i.GoVersion)
}
