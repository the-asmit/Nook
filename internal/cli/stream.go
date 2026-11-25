package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// errStreamDone ends an event stream normally from its handler.
var errStreamDone = errors.New("stream done")

// maxEventLine bounds one line of a Server-Sent Events stream.
const maxEventLine = 1 << 20

// stream reads a Server-Sent Events response, calling handle for each
// event. It has no overall timeout (a build can run for many minutes);
// cancel ctx to stop. Returning errStreamDone from handle ends it cleanly.
func (c *client) stream(ctx context.Context, path string, handle func(event string, data []byte) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", "Bearer "+c.token)
	hc := &http.Client{Transport: c.http.Transport, CheckRedirect: c.http.CheckRedirect}
	resp, err := hc.Do(req)
	if err != nil {
		return unwrapURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return decodeAPIError(resp, data)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), maxEventLine)
	var event string
	var data bytes.Buffer
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if event != "" {
				if err := handle(event, data.Bytes()); err != nil {
					if errors.Is(err, errStreamDone) {
						return nil
					}
					return err
				}
			}
			event = ""
			data.Reset()
		case strings.HasPrefix(line, ":"):
			// keepalive comment
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("read event stream: %w", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("the server closed the log stream before the build ended")
}

// text GETs a text/plain resource.
func (c *client) text(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", unwrapURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return "", decodeAPIError(resp, data)
	}
	return string(data), nil
}

// unwrapURLError drops the request URL from transport errors: presigned
// URLs are credentials and must not end up in terminal scrollback.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
