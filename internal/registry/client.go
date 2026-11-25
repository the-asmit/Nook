package registry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/the-asmit/nook/internal/pki"
	"github.com/the-asmit/nook/internal/platform/config"
)

// Config locates the registry.
type Config struct {
	// Addr is the registry's host:port as worker nodes reach it; images
	// are referenced as Addr/<repository>@<digest>.
	Addr string `env:"NOOK_REGISTRY_ADDR"`
	// URL is how the control plane reaches the registry API. Defaults to
	// https://Addr.
	URL string `env:"NOOK_REGISTRY_URL"`
	// Service and Issuer must match auth.token.service and .issuer in the
	// registry configuration.
	Service string `env:"NOOK_REGISTRY_SERVICE" envDefault:"nook-registry"`
	Issuer  string `env:"NOOK_REGISTRY_TOKEN_ISSUER" envDefault:"nook"`
	// GCSecret authenticates the registry's garbage-collection job when it
	// asks for a maintenance window.
	GCSecret config.Secret `env:"NOOK_REGISTRY_GC_SECRET"`
	// RequestTimeout bounds each registry API call.
	RequestTimeout time.Duration `env:"NOOK_REGISTRY_REQUEST_TIMEOUT" envDefault:"30s"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	if host, port, err := net.SplitHostPort(c.Addr); err != nil || host == "" || port == "" {
		errs = append(errs, fmt.Errorf("NOOK_REGISTRY_ADDR: must be host:port, got %q", c.Addr))
	}
	if c.URL != "" {
		u, err := url.Parse(c.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || strings.Trim(u.Path, "/") != "" {
			errs = append(errs, fmt.Errorf("NOOK_REGISTRY_URL: must be an https:// URL without path, got %q", c.URL))
		}
	}
	if c.Service == "" || c.Issuer == "" {
		errs = append(errs, errors.New("NOOK_REGISTRY_SERVICE and NOOK_REGISTRY_TOKEN_ISSUER: required"))
	}
	if len(c.GCSecret.Reveal()) < 16 {
		errs = append(errs, errors.New("NOOK_REGISTRY_GC_SECRET: at least 16 characters required"))
	}
	errs = append(errs, config.CheckDuration("NOOK_REGISTRY_REQUEST_TIMEOUT", c.RequestTimeout, time.Second, 10*time.Minute))
	return errors.Join(errs...)
}

// BaseURL is the registry API base URL.
func (c *Config) BaseURL() string {
	if c.URL != "" {
		return strings.TrimRight(c.URL, "/")
	}
	return "https://" + c.Addr
}

// digestPattern is a sha256 content digest.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidDigest reports whether s is a sha256 digest.
func ValidDigest(s string) bool { return digestPattern.MatchString(s) }

// Client calls the registry API with tokens from an Issuer.
type Client struct {
	base    string
	issuer  *Issuer
	timeout time.Duration
	http    *http.Client
}

// NewClient returns a client that trusts only the internal CA.
func NewClient(cfg *Config, issuer *Issuer, ca *pki.CA) *Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca.Pool()},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	return &Client{base: cfg.BaseURL(), issuer: issuer, timeout: cfg.RequestTimeout, http: &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// ErrNotFound means the repository or manifest does not exist.
var ErrNotFound = errors.New("not found in registry")

// manifestTypes are the manifest media types Nook's builds produce.
var manifestTypes = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

// ManifestExists reports whether repo holds a manifest with digest.
func (c *Client) ManifestExists(ctx context.Context, repo, digest string) (bool, error) {
	resp, err := c.request(ctx, http.MethodHead, "/v2/"+repo+"/manifests/"+digest, RepositoryAccess(repo, ActionPull))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	closeBody(resp)
	return true, nil
}

// TagDigest returns the manifest digest a tag points to.
func (c *Client) TagDigest(ctx context.Context, repo, tag string) (string, error) {
	resp, err := c.request(ctx, http.MethodHead, "/v2/"+repo+"/manifests/"+tag, RepositoryAccess(repo, ActionPull))
	if err != nil {
		return "", err
	}
	defer closeBody(resp)
	d := resp.Header.Get("Docker-Content-Digest")
	if !ValidDigest(d) {
		return "", fmt.Errorf("registry returned no digest for %s:%s", repo, tag)
	}
	return d, nil
}

// DeleteManifest deletes a manifest by digest; deleting a missing one
// succeeds. The blobs it referenced are reclaimed by garbage collection.
func (c *Client) DeleteManifest(ctx context.Context, repo, digest string) error {
	resp, err := c.request(ctx, http.MethodDelete, "/v2/"+repo+"/manifests/"+digest, RepositoryAccess(repo, ActionDelete))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	closeBody(resp)
	return nil
}

// Tags lists a repository's tags (empty if the repository does not exist).
func (c *Client) Tags(ctx context.Context, repo string) ([]string, error) {
	var out struct {
		Tags []string `json:"tags"`
	}
	err := c.getJSON(ctx, "/v2/"+repo+"/tags/list?n=1000", &out, RepositoryAccess(repo, ActionPull))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return out.Tags, err
}

// catalogPage is the page size for listing repositories (the registry
// rejects larger pages).
const catalogPage = 1000

// Repositories lists every repository in the registry.
func (c *Client) Repositories(ctx context.Context) ([]string, error) {
	var all []string
	last := ""
	for {
		var out struct {
			Repositories []string `json:"repositories"`
		}
		path := "/v2/_catalog?n=" + strconv.Itoa(catalogPage)
		if last != "" {
			path += "&last=" + url.QueryEscape(last)
		}
		if err := c.getJSON(ctx, path, &out, CatalogAccess()); err != nil {
			return nil, err
		}
		all = append(all, out.Repositories...)
		if len(out.Repositories) < catalogPage {
			return all, nil
		}
		last = out.Repositories[len(out.Repositories)-1]
	}
}

func (c *Client) getJSON(ctx context.Context, path string, dst any, access Access) error {
	resp, err := c.request(ctx, http.MethodGet, path, access)
	if err != nil {
		return err
	}
	defer closeBody(resp)
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(dst); err != nil {
		return fmt.Errorf("decode registry response: %w", err)
	}
	return nil
}

func (c *Client) request(ctx context.Context, method, path string, access Access) (*http.Response, error) {
	token, err := c.issuer.Token("nook-control-plane", 5*time.Minute, access)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, http.NoBody)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("registry %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", manifestTypes)
	resp, err := c.http.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("registry %s %s: %w", method, path, err)
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	switch {
	case resp.StatusCode < 300:
		return resp, nil
	case resp.StatusCode == http.StatusNotFound:
		closeBody(resp)
		return nil, fmt.Errorf("registry %s %s: %w", method, path, ErrNotFound)
	default:
		closeBody(resp)
		return nil, fmt.Errorf("registry %s %s: HTTP %d", method, path, resp.StatusCode)
	}
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

func closeBody(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}
