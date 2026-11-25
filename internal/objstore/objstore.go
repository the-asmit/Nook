// Package objstore talks to Nook's S3-compatible object storage (MinIO in
// development, Cloudflare R2 or any S3 service in production): presigned
// upload and download URLs for clients and agents, and the few
// authenticated calls the control plane makes itself.
//
// It deliberately speaks plain S3 (Signature Version 4) with the standard
// library instead of a vendor SDK: Nook uses half a dozen operations and
// must control exactly which headers a presigned URL pins.
package objstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/the-asmit/nook/internal/platform/config"
)

// Config selects the bucket and credentials.
type Config struct {
	// Endpoint is the S3 API base URL, e.g. https://<account>.r2.cloudflarestorage.com.
	Endpoint string `env:"NOOK_S3_ENDPOINT"`
	// PresignEndpoint is the base URL put into presigned URLs, for when
	// clients and agents reach storage under another name than the control
	// plane does. Defaults to Endpoint.
	PresignEndpoint string        `env:"NOOK_S3_PRESIGN_ENDPOINT"`
	Region          string        `env:"NOOK_S3_REGION" envDefault:"us-east-1"`
	Bucket          string        `env:"NOOK_S3_BUCKET" envDefault:"nook"`
	AccessKeyID     string        `env:"NOOK_S3_ACCESS_KEY_ID"`
	SecretAccessKey config.Secret `env:"NOOK_S3_SECRET_ACCESS_KEY"`
	// RequestTimeout bounds each call the control plane makes.
	RequestTimeout time.Duration `env:"NOOK_S3_REQUEST_TIMEOUT" envDefault:"30s"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var errs []error
	for name, raw := range map[string]string{"NOOK_S3_ENDPOINT": c.Endpoint, "NOOK_S3_PRESIGN_ENDPOINT": c.PresignEndpoint} {
		if raw == "" && name == "NOOK_S3_PRESIGN_ENDPOINT" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
			u.RawQuery != "" || strings.Trim(u.Path, "/") != "" {
			errs = append(errs, fmt.Errorf("%s: must be an http(s) URL without path, got %q", name, raw))
		}
	}
	if !validBucket(c.Bucket) {
		errs = append(errs, fmt.Errorf("NOOK_S3_BUCKET: invalid bucket name %q", c.Bucket))
	}
	if c.Region == "" || len(c.Region) > 64 {
		errs = append(errs, errors.New("NOOK_S3_REGION: required"))
	}
	if c.AccessKeyID == "" || c.SecretAccessKey.IsZero() {
		errs = append(errs, errors.New("NOOK_S3_ACCESS_KEY_ID and NOOK_S3_SECRET_ACCESS_KEY: required"))
	}
	errs = append(errs, config.CheckDuration("NOOK_S3_REQUEST_TIMEOUT", c.RequestTimeout, time.Second, 10*time.Minute))
	return errors.Join(errs...)
}

// TLS reports whether both endpoints use https.
func (c *Config) TLS() bool {
	return strings.HasPrefix(c.Endpoint, "https://") &&
		(c.PresignEndpoint == "" || strings.HasPrefix(c.PresignEndpoint, "https://"))
}

func validBucket(b string) bool {
	if len(b) < 3 || len(b) > 63 {
		return false
	}
	for i := range len(b) {
		c := b[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return b[0] != '-' && b[0] != '.' && b[len(b)-1] != '-' && b[len(b)-1] != '.'
}

// ErrNotFound means the object (or bucket) does not exist.
var ErrNotFound = errors.New("object not found")

// Client is an S3 client for one bucket. URLs are path-style
// (endpoint/bucket/key), which every S3-compatible service accepts.
type Client struct {
	endpoint *url.URL
	presign  *url.URL
	bucket   string
	creds    credentials
	timeout  time.Duration
	http     *http.Client
	now      func() time.Time
}

// New returns a client. httpClient may be nil.
func New(cfg *Config, httpClient *http.Client) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ep, _ := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	pre := ep
	if cfg.PresignEndpoint != "" {
		pre, _ = url.Parse(strings.TrimRight(cfg.PresignEndpoint, "/"))
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{
		endpoint: ep, presign: pre, bucket: cfg.Bucket, timeout: cfg.RequestTimeout, http: httpClient, now: time.Now,
		creds: credentials{accessKeyID: cfg.AccessKeyID, secret: cfg.SecretAccessKey.Reveal(), region: cfg.Region},
	}, nil
}

// Bucket returns the bucket name.
func (c *Client) Bucket() string { return c.bucket }

func (c *Client) objectURL(base *url.URL, key string) *url.URL {
	u := *base
	u.Path = "/" + c.bucket
	if key != "" {
		u.Path += "/" + key
	}
	return &u
}

// Upload describes how to upload with a presigned URL: the URL, the
// method and the headers that must be sent exactly as given.
type Upload struct {
	URL       string            `json:"url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// PresignPut returns a presigned PUT for key that only accepts a body of
// exactly size bytes whose SHA-256 is sum: both are signed headers, and
// the storage service verifies the checksum against the received bytes.
func (c *Client) PresignPut(key string, size int64, sum []byte, expires time.Duration) Upload {
	now := c.now()
	headers := map[string]string{
		"content-length":        strconv.FormatInt(size, 10),
		"x-amz-checksum-sha256": base64.StdEncoding.EncodeToString(sum),
	}
	return Upload{
		URL:    c.creds.presign(http.MethodPut, c.objectURL(c.presign, key), now, expires, headers),
		Method: http.MethodPut,
		// Content-Length is set by HTTP clients from the body itself.
		Headers:   map[string]string{"x-amz-checksum-sha256": headers["x-amz-checksum-sha256"]},
		ExpiresAt: now.Add(expires).UTC(),
	}
}

// PresignGet returns a presigned GET URL for key.
func (c *Client) PresignGet(key string, expires time.Duration) string {
	return c.creds.presign(http.MethodGet, c.objectURL(c.presign, key), c.now(), expires, nil)
}

// ObjectInfo is what HEAD reports.
type ObjectInfo struct {
	Size int64
	// SHA256 is the checksum the service verified at upload, or nil if it
	// stored none.
	SHA256 []byte
}

// Head returns an object's size and stored SHA-256 checksum.
func (c *Client) Head(ctx context.Context, key string) (ObjectInfo, error) {
	resp, err := c.do(ctx, http.MethodHead, key, nil, map[string]string{"x-amz-checksum-mode": "ENABLED"})
	if err != nil {
		return ObjectInfo{}, err
	}
	defer drain(resp)
	info := ObjectInfo{Size: resp.ContentLength}
	if v := resp.Header.Get("X-Amz-Checksum-Sha256"); v != "" {
		if sum, err := base64.StdEncoding.DecodeString(v); err == nil && len(sum) == sha256.Size {
			info.SHA256 = sum
		}
	}
	return info, nil
}

// Put stores body (which is small enough to hold in memory) under key.
func (c *Client) Put(ctx context.Context, key, contentType string, body []byte) error {
	headers := map[string]string{"content-type": contentType}
	resp, err := c.do(ctx, http.MethodPut, key, body, headers)
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// Get reads a whole object, refusing objects larger than maxBytes.
func (c *Client) Get(ctx context.Context, key string, maxBytes int64) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, key, nil, nil)
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("object %s is larger than %d bytes", key, maxBytes)
	}
	return data, nil
}

// Delete removes an object; deleting a missing object succeeds.
func (c *Client) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// EnsureBucket creates the bucket if it does not exist.
func (c *Client) EnsureBucket(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodHead, "", nil, nil)
	if err == nil {
		drain(resp)
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	resp, err = c.do(ctx, http.MethodPut, "", nil, nil)
	var se *Error
	if errors.As(err, &se) && (se.Code == "BucketAlreadyOwnedByYou" || se.Code == "BucketAlreadyExists") {
		return nil
	}
	if err != nil {
		return err
	}
	drain(resp)
	return nil
}

// Error is an error response from the storage service.
type Error struct {
	Op     string
	Key    string
	Status int
	Code   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("object storage %s %q: HTTP %d %s", e.Op, e.Key, e.Status, e.Code)
}

// do sends a signed request. It never puts the request URL into errors:
// for presigned-style or signed requests that URL is a credential.
func (c *Client) do(ctx context.Context, method, key string, body []byte, headers map[string]string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	u := c.objectURL(c.endpoint, key)
	u.RawPath = uriEncode(u.Path, true)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("object storage %s %q: build request: %w", method, key, err)
	}
	req.ContentLength = int64(len(body))
	if body == nil {
		req.Body = http.NoBody
	}
	payload := sha256.Sum256(body)
	c.creds.signRequest(req, c.now(), hex.EncodeToString(payload[:]), headers)
	resp, err := c.http.Do(req)
	if err != nil {
		cancel()
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("object storage %s %q: %w", method, key, err)
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	if resp.StatusCode < 300 {
		return resp, nil
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("object storage %s %q: %w", method, key, ErrNotFound)
	}
	e := &Error{Op: method, Key: key, Status: resp.StatusCode}
	var xmlErr struct {
		Code string `xml:"Code"`
	}
	if data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10)); err == nil && xml.Unmarshal(data, &xmlErr) == nil {
		e.Code = xmlErr.Code
	}
	return nil, e
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

func formatSeconds(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10)
}
