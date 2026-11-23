// Package logging builds the structured JSON logger every Nook binary uses
// and carries per-request attributes, such as the request ID, through
// context.Context so that any log line written while serving a request can
// be correlated with it.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Config controls log output.
type Config struct {
	// Level is the minimum level written: debug, info, warn or error.
	Level string `env:"NOOK_LOG_LEVEL" envDefault:"info"`
}

// Validate checks that the level is one of the supported names.
func (c *Config) Validate() error {
	if _, err := ParseLevel(c.Level); err != nil {
		return fmt.Errorf("NOOK_LOG_LEVEL: %w", err)
	}
	return nil
}

// ParseLevel converts a level name into a slog.Level. Only the four plain
// names are accepted; slog's "info+2" offset syntax is deliberately
// rejected to keep configuration obvious.
func ParseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("must be one of debug, info, warn or error, got %q", name)
	}
}

// New returns a JSON logger writing to w at the configured level. The given
// attributes (service name, version, ...) are attached to every record.
func New(w io.Writer, cfg Config, attrs ...slog.Attr) (*slog.Logger, error) {
	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("NOOK_LOG_LEVEL: %w", err)
	}
	var handler slog.Handler = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	handler = contextHandler{Handler: handler.WithAttrs(attrs)}
	return slog.New(handler), nil
}

type requestIDKey struct{}

// WithRequestID returns a copy of ctx carrying the request ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext returns the request ID stored in ctx, or "" if none.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// contextHandler adds the request ID from the record's context, so callers
// only need to use the *Context logging methods to get correlation.
type contextHandler struct {
	slog.Handler
}

// Handle implements slog.Handler.
//
//nolint:gocritic // hugeParam: slog.Handler fixes the signature; Record is passed by value by design.
func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestIDFromContext(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	if err := h.Handler.Handle(ctx, r); err != nil {
		return fmt.Errorf("write log record: %w", err)
	}
	return nil
}

// WithAttrs implements slog.Handler.
func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup implements slog.Handler.
func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{Handler: h.Handler.WithGroup(name)}
}
