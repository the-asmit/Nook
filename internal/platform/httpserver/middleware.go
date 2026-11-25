package httpserver

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/platform/logging"
)

// HeaderRequestID carries the request ID in requests and responses.
const HeaderRequestID = "X-Request-ID"

// maxRequestIDLength bounds accepted incoming IDs; UUIDs are 36 characters.
const maxRequestIDLength = 64

// RequestID reuses a well-formed incoming X-Request-ID (so a trace can span
// the gateway and the control plane) or generates a new one. The ID is
// echoed in the response and stored in the request context for logging.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(HeaderRequestID)
		if !validRequestID(id) {
			// 128 random bits, base32: unique without coordination.
			id = rand.Text()
		}
		c.Request = c.Request.WithContext(logging.WithRequestID(c.Request.Context(), id))
		c.Header(HeaderRequestID, id)
		c.Next()
	}
}

// validRequestID accepts only short tokens of URL-safe characters, so a
// client cannot inject control characters or huge values into our logs.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLength {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// SecurityHeaders sets defensive response headers. The control-plane API
// only ever returns JSON, so the content security policy forbids loading
// anything at all.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// API responses may contain private data; never let caches keep them.
		h.Set("Cache-Control", "no-store")
		if c.Request.TLS != nil {
			// Only meaningful (and only honored by browsers) over HTTPS.
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		c.Next()
	}
}

// BodyLimit rejects requests whose body exceeds maxBytes. A declared
// Content-Length over the limit is refused before reading anything;
// otherwise the body is wrapped so that reading past the limit fails.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			AbortWithError(c, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("request body must not exceed %d bytes", maxBytes))
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// RequestTimeout puts a deadline on the request context. Handlers and the
// database/Redis calls they make observe it and give up in time.
//
// This deliberately does not run the handler in a second goroutine the way
// http.TimeoutHandler does: with Gin that races on the response writer.
// Instead, if a handler returns without writing anything after the
// deadline passed, a 503 is sent on its behalf.
//
// Streaming routes (listed by their route template) are exempt: they stay
// open for as long as the client listens and manage their own deadlines.
func RequestTimeout(timeout time.Duration, streamingRoutes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if slices.Contains(streamingRoutes, c.FullPath()) {
			c.Next()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) && !c.Writer.Written() {
			AbortWithError(c, http.StatusServiceUnavailable, "timeout", "the request took too long to process")
		}
	}
}
