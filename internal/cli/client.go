package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// requestTimeout bounds every API call.
const requestTimeout = 30 * time.Second

// maxResponseSize bounds how much of a response the CLI reads.
const maxResponseSize = 4 << 20

// APIError is an error response from the Nook API.
type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%s (HTTP %d, %s)", e.Message, e.Status, e.Code)
	if e.RequestID != "" {
		msg += " [request ID " + e.RequestID + "]"
	}
	return msg
}

// client calls the Nook REST API.
type client struct {
	base      string
	token     string
	userAgent string
	http      *http.Client
}

func newClient(server, token, userAgent string) (*client, error) {
	base, err := normalizeServer(server)
	if err != nil {
		return nil, err
	}
	return &client{
		base:      base,
		token:     token,
		userAgent: userAgent,
		// Never follow redirects: an API call that redirects is a
		// misconfiguration, and following one could send the token elsewhere.
		http: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// normalizeServer validates a server URL ("https://nook.example.com").
func normalizeServer(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" {
		return "", fmt.Errorf("invalid server URL %q: use https://host[:port]", raw)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return "", fmt.Errorf("refusing plain http:// for %s: tokens would travel unencrypted; use https://", u.Host)
	}
	return raw, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// do sends a request and decodes a JSON response into out (if non-nil).
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var reader io.Reader = http.NoBody
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return decodeAPIError(resp, data)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response from %s: %w", path, err)
	}
	return nil
}

func decodeAPIError(resp *http.Response, data []byte) error {
	var env struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	e := &APIError{Status: resp.StatusCode, RequestID: resp.Header.Get("X-Request-ID")}
	if json.Unmarshal(data, &env) == nil && env.Error.Code != "" {
		e.Code, e.Message = env.Error.Code, env.Error.Message
		if env.Error.RequestID != "" {
			e.RequestID = env.Error.RequestID
		}
		return e
	}
	e.Code, e.Message = "http_error", http.StatusText(resp.StatusCode)
	return e
}

// isAPIError reports whether err is an API error with the given code.
func isAPIError(err error, code string) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == code
}
