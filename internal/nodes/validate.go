package nodes

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/auth"
)

// JoinTokenPrefix marks node join tokens.
const JoinTokenPrefix = "nook_join_"

// NewJoinToken returns a new join token and its display prefix.
func NewJoinToken() (token, prefix string) {
	token = JoinTokenPrefix + auth.NewSecret()
	return token, token[:len(JoinTokenPrefix)+4]
}

// LooksLikeJoinToken checks a presented token's shape before any lookup.
func LooksLikeJoinToken(s string) bool {
	rest, ok := strings.CutPrefix(s, JoinTokenPrefix)
	return ok && auth.LooksLikeSecret(rest)
}

var (
	nodeNamePattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	labelKeyPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9._/-]{0,61}[a-z0-9])?$`)
	labelValuePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{0,63}$`)
)

// maxLabels bounds how many labels a node may carry.
const maxLabels = 32

// ValidNodeName reports whether s is an acceptable node name.
func ValidNodeName(s string) bool {
	return nodeNamePattern.MatchString(s)
}

// normalizeNodeName returns the requested name, or one derived from the
// hostname ("Build-Server.local" -> "build-server-local").
func normalizeNodeName(requested, hostname string) (string, error) {
	if requested != "" {
		if !ValidNodeName(requested) {
			return "", apperr.Invalid("invalid_name", "node name must be 1 to 63 lower-case letters, digits or inner hyphens")
		}
		return requested, nil
	}
	var b strings.Builder
	for _, r := range strings.ToLower(hostname) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-")
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	if !ValidNodeName(name) {
		return "", apperr.Invalid("invalid_name", "cannot derive a node name from the hostname; pass --name")
	}
	return name, nil
}

// ParseLabels parses "k=v,k2=v2" as given on the command line.
func ParseLabels(s string) (map[string]string, error) {
	out := map[string]string{}
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for pair := range strings.SplitSeq(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			return nil, fmt.Errorf("label %q must be key=value", pair)
		}
		out[k] = v
	}
	if _, err := encodeLabels(out); err != nil {
		return nil, err
	}
	return out, nil
}

func encodeLabels(labels map[string]string) ([]byte, error) {
	if len(labels) > maxLabels {
		return nil, apperr.Invalid("invalid_labels", "at most %d labels are allowed", maxLabels)
	}
	for k, v := range labels {
		if !labelKeyPattern.MatchString(k) {
			return nil, apperr.Invalid("invalid_labels", "label key %q must be lower-case letters, digits, '.', '_', '/', '-'", k)
		}
		if !labelValuePattern.MatchString(v) {
			return nil, apperr.Invalid("invalid_labels", "label value for %q must be at most 63 letters, digits, '.', '_', '-'", k)
		}
	}
	if labels == nil {
		labels = map[string]string{}
	}
	data, err := json.Marshal(labels)
	if err != nil {
		return nil, fmt.Errorf("encode labels: %w", err)
	}
	return data, nil
}

// Info is what an agent reports about its node.
type Info struct {
	Hostname         string
	Addresses        []string
	CPUCount         int32
	MemoryTotalBytes int64
	DiskTotalBytes   int64
	DockerVersion    string
	AgentVersion     string
	OS               string
	Arch             string
	// BuildSlots is how many builds the agent runs at once (0..64).
	BuildSlots int32
}

// sanitized bounds everything an agent reports, since it is stored and
// displayed: overlong strings are cut, invalid addresses dropped.
func (i *Info) sanitized() Info {
	out := Info{
		Hostname:         clean(i.Hostname, 253),
		CPUCount:         max(i.CPUCount, 0),
		MemoryTotalBytes: max(i.MemoryTotalBytes, 0),
		DiskTotalBytes:   max(i.DiskTotalBytes, 0),
		DockerVersion:    clean(i.DockerVersion, 64),
		AgentVersion:     clean(i.AgentVersion, 64),
		OS:               clean(i.OS, 32),
		Arch:             clean(i.Arch, 32),
		BuildSlots:       min(max(i.BuildSlots, 0), 64),
		Addresses:        []string{},
	}
	for _, a := range i.Addresses {
		if addr, err := netip.ParseAddr(a); err == nil && len(out.Addresses) < 16 {
			out.Addresses = append(out.Addresses, addr.String())
		}
	}
	return out
}

func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
