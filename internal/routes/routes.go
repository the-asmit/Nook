// Package routes is what the control plane and the gateway share about
// app routes: the host-name scheme, the route record the gateway serves
// from, and the Redis Pub/Sub channel that announces changes.
//
// App URLs are <scheme>://<app>--<workspace>.<apps domain>[:port]: one DNS
// label under the apps domain, so a single wildcard certificate (or one
// certificate per host) covers every app. The auth host is
// auth.<apps domain>; "auth" cannot be an app label because app labels
// always contain "--".
package routes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"uuid"

	goredis "github.com/redis/go-redis/v9"
)

// Channel carries the ID of an app whose route changed.
const Channel = "nook:routes"

// AuthLabel is the auth host's label under the apps domain.
const AuthLabel = "auth"

// maxLabel is the DNS limit for one label.
const maxLabel = 63

// Separator joins app and workspace slugs in a host label.
const Separator = "--"

// Route states.
const (
	StateRunning     = "running"      // healthy: proxied
	StateUnhealthy   = "unhealthy"    // restarting after a crash: proxied, may fail
	StateStarting    = "starting"     // a new instance is starting
	StateCrashed     = "crashed"      // crash loop: not restarted
	StateStopped     = "stopped"      // stopped by its owners
	StateNotDeployed = "not_deployed" // nothing released yet
)

// Access modes.
const (
	AccessWorkspace  = "workspace"
	AccessRestricted = "restricted"
	AccessPublic     = "public"
)

// Route is how the gateway serves one app host.
type Route struct {
	AppID     uuid.UUID `json:"app_id"`
	Host      string    `json:"host"`
	Workspace string    `json:"workspace"`
	App       string    `json:"app"`
	// Access is the effective mode (public only where the instance
	// allows public apps).
	Access string `json:"access"`
	State  string `json:"state"`
	// Upstream is the instance's address:port on its node, when served.
	Upstream string `json:"upstream,omitempty"`
}

// Serving reports whether requests are proxied to the upstream.
func (r *Route) Serving() bool {
	return r.Upstream != "" && (r.State == StateRunning || r.State == StateUnhealthy)
}

// Base is the apps domain with the scheme and port app URLs use.
type Base struct {
	Scheme string // http (development) or https
	Domain string // e.g. apps.example.com
	Port   string // empty for the scheme's default
}

// ParseBase reads NOOK_APPS_BASE_URL, e.g. https://apps.example.com or
// http://apps.localhost:8081.
func ParseBase(raw string) (Base, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return Base{}, errors.New("must be http(s)://<apps domain>[:port] with no path")
	}
	domain := strings.ToLower(u.Hostname())
	if net.ParseIP(domain) != nil || !strings.Contains(domain, ".") || len(domain) >= 253-maxLabel {
		return Base{}, errors.New("the apps domain must be a DNS name with at least two labels (e.g. apps.example.com or apps.localhost)")
	}
	return Base{Scheme: u.Scheme, Domain: domain, Port: u.Port()}, nil
}

// Label is an app's host label.
func Label(workspace, app string) string { return app + Separator + workspace }

// ValidLabel reports whether an app and workspace slug fit in one label.
func ValidLabel(workspace, app string) bool {
	return len(Label(workspace, app)) <= maxLabel && !strings.Contains(app, Separator) && !strings.Contains(workspace, Separator)
}

// Host is an app's host name.
func (b Base) Host(workspace, app string) string { return Label(workspace, app) + "." + b.Domain }

// AuthHost is the auth host's name.
func (b Base) AuthHost() string { return AuthLabel + "." + b.Domain }

// Origin is scheme://host[:port] for a host under the apps domain.
func (b Base) Origin(host string) string {
	if b.Port != "" {
		host = net.JoinHostPort(host, b.Port)
	}
	return b.Scheme + "://" + host
}

// URL is an app's URL.
func (b Base) URL(workspace, app string) string { return b.Origin(b.Host(workspace, app)) + "/" }

// Parse splits an app host name into workspace and app slugs. ok is false
// for the auth host and for names that are not app hosts.
func (b Base) Parse(host string) (workspace, app string, ok bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	label, found := strings.CutSuffix(host, "."+b.Domain)
	if !found || strings.Contains(label, ".") {
		return "", "", false
	}
	app, workspace, found = strings.Cut(label, Separator)
	if !found || app == "" || workspace == "" || strings.Contains(workspace, Separator) {
		return "", "", false
	}
	return workspace, app, true
}

// StripPort removes a port from a Host header value.
func StripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// Publisher announces route changes.
type Publisher struct {
	redis *goredis.Client
}

// NewPublisher returns a publisher.
func NewPublisher(rdb *goredis.Client) *Publisher { return &Publisher{redis: rdb} }

// Changed announces that an app's route may have changed. Gateways that
// miss it catch up at their next full resync, so failures only delay.
func (p *Publisher) Changed(ctx context.Context, appID uuid.UUID) {
	_ = p.redis.Publish(ctx, Channel, appID.String()).Err()
}

// ErrNotFound means there is no such route.
var ErrNotFound = errors.New("route not found")

// Effective returns the access mode in force.
func Effective(mode string, allowPublic bool) string {
	if mode == AccessPublic && !allowPublic {
		return AccessWorkspace
	}
	return mode
}

// StateOf derives a route state from an app's desired state and its
// newest instance.
func StateOf(desired string, hasDeployment bool, instanceState string) string {
	switch {
	case desired == "stopped":
		return StateStopped
	case !hasDeployment:
		return StateNotDeployed
	}
	switch instanceState {
	case "healthy":
		return StateRunning
	case "unhealthy":
		return StateUnhealthy
	case "crashed", "failed":
		return StateCrashed
	case "stopping", "stopped":
		return StateStopped
	default:
		return StateStarting
	}
}

// Describe is a visitor-facing sentence for a route that is not served.
func Describe(state string) string {
	switch state {
	case StateStopped:
		return "This app is stopped."
	case StateCrashed:
		return "This app has crashed and is not running."
	case StateStarting:
		return "This app is starting. Try again in a moment."
	case StateNotDeployed:
		return "This app has not been deployed yet."
	default:
		return fmt.Sprintf("This app is not available (%s).", state)
	}
}
