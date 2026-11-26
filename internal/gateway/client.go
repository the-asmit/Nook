package gateway

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
	"uuid"

	"github.com/the-asmit/nook/internal/routes"
)

// cpTimeout bounds one call to the control plane.
const cpTimeout = 10 * time.Second

// errNotFound is a 404 from the control plane.
var errNotFound = errors.New("not found")

// statusError is any other unsuccessful status from the control plane.
type statusError struct {
	method, path string
	code         int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("control plane %s %s: HTTP %d", e.method, e.path, e.code)
}

// controlPlane calls the control plane's internal API.
type controlPlane struct {
	base   string
	secret string
	http   *http.Client
}

func newControlPlane(base, secret string) *controlPlane {
	return &controlPlane{
		base: strings.TrimRight(base, "/"), secret: secret,
		http: &http.Client{Timeout: cpTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (c *controlPlane) do(ctx context.Context, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, cpTimeout)
	defer cancel()
	var body io.Reader = http.NoBody
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("control plane %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("read control plane response: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.StatusCode >= 300:
		return &statusError{method: method, path: path, code: resp.StatusCode}
	case out == nil || len(data) == 0:
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode control plane response: %w", err)
	}
	return nil
}

func (c *controlPlane) routes(ctx context.Context) ([]routes.Route, error) {
	var out struct {
		Routes []routes.Route `json:"routes"`
	}
	err := c.do(ctx, http.MethodGet, "/internal/v1/routes", nil, &out)
	return out.Routes, err
}

func (c *controlPlane) route(ctx context.Context, appID uuid.UUID) (routes.Route, error) {
	var r routes.Route
	err := c.do(ctx, http.MethodGet, "/internal/v1/routes/"+appID.String(), nil, &r)
	if errors.Is(err, errNotFound) {
		return routes.Route{}, routes.ErrNotFound
	}
	return r, err
}

// knownHost asks whether a certificate may be requested for host.
func (c *controlPlane) knownHost(ctx context.Context, host string) (bool, error) {
	err := c.do(ctx, http.MethodGet, "/internal/v1/tls/hosts/"+url.PathEscape(host), nil, nil)
	if errors.Is(err, errNotFound) {
		return false, nil
	}
	return err == nil, err
}

type exchanged struct {
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
	ReturnPath string    `json:"return_path"`
}

// errInvalidCode means the control plane refused a code.
var errInvalidCode = errors.New("invalid sign-in code")

func (c *controlPlane) exchange(ctx context.Context, code, host string) (exchanged, error) {
	var out exchanged
	err := c.do(ctx, http.MethodPost, "/internal/v1/visitor/exchange", map[string]string{"code": code, "host": host}, &out)
	if se := (*statusError)(nil); errors.As(err, &se) && se.code == http.StatusBadRequest {
		return out, errInvalidCode
	}
	return out, err
}

type checked struct {
	Status string `json:"status"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

func (c *controlPlane) check(ctx context.Context, token, host string) (checked, error) {
	var out checked
	err := c.do(ctx, http.MethodPost, "/internal/v1/visitor/check", map[string]string{"token": token, "host": host}, &out)
	return out, err
}

func (c *controlPlane) signOut(ctx context.Context, token string) error {
	return c.do(ctx, http.MethodPost, "/internal/v1/visitor/sign-out", map[string]string{"token": token}, nil)
}

// Certificate storage for autocert (see tls.go).

func (c *controlPlane) getCert(ctx context.Context, name string) ([]byte, error) {
	var out struct {
		Data []byte `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, "/internal/v1/certificates/"+url.PathEscape(name), nil, &out)
	return out.Data, err
}

func (c *controlPlane) putCert(ctx context.Context, name string, data []byte) error {
	return c.do(ctx, http.MethodPut, "/internal/v1/certificates/"+url.PathEscape(name), map[string][]byte{"data": data}, nil)
}

func (c *controlPlane) deleteCert(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/internal/v1/certificates/"+url.PathEscape(name), nil, nil)
}
