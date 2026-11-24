package config

import (
	"net/netip"
	"strings"
)

// IsInternalHost reports whether host is reachable only inside a private
// network: a Unix socket path, a loopback or private (RFC 1918, IPv6 ULA)
// address, "localhost", or a single-label name such as a Docker Compose
// service name ("postgres"). Dotted host names are never considered
// internal, because their resolution cannot be checked here.
func IsInternalHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "/") {
		return true
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		addr = addr.Unmap()
		return addr.IsLoopback() || addr.IsPrivate()
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	return !strings.Contains(host, ".") && validLabel(host)
}

// IsLoopbackHost reports whether host is localhost or a loopback address.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && addr.Unmap().IsLoopback()
}

func validLabel(s string) bool {
	if len(s) > 63 || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
