package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// maxHeaderBytes caps request header size; Go's default of 1 MiB is far
// more than any legitimate API client sends.
const maxHeaderBytes = 64 << 10

// Server is an HTTP(S) server bound to a listener.
type Server struct {
	srv             *http.Server
	listener        net.Listener
	shutdownTimeout time.Duration
	tls             bool
	logger          *slog.Logger
}

// Listen binds the listen address immediately, so a port conflict is
// reported at startup rather than from a background goroutine, and
// returns a Server ready to Serve handler.
func Listen(ctx context.Context, cfg *Config, handler http.Handler, logger *slog.Logger) (*Server, error) {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		// Route net/http's own error messages (TLS handshake failures,
		// malformed requests) through the structured logger.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	if cfg.TLSEnabled() {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate: %w", err)
		}
		// Every client of Nook's internal APIs (the gateway, the CLI,
		// Prometheus) is modern Go or a current browser, so older protocol
		// versions are not worth their downgrade risk.
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", cfg.Addr, err)
	}
	return &Server{
		srv:             srv,
		listener:        ln,
		shutdownTimeout: cfg.ShutdownTimeout,
		tls:             cfg.TLSEnabled(),
		logger:          logger,
	}, nil
}

// Addr returns the bound address (useful when listening on port 0).
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// Serve handles requests until ctx is done, then shuts down gracefully:
// the listener closes at once, idle keep-alive connections are closed, and
// in-flight requests get the shutdown timeout to finish before the
// remaining connections are cut.
func (s *Server) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if s.tls {
			errCh <- s.srv.ServeTLS(s.listener, "", "")
			return
		}
		errCh <- s.srv.Serve(s.listener)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server stopped unexpectedly: %w", err)
	case <-ctx.Done():
	}

	s.logger.InfoContext(ctx, "shutting down http server; draining in-flight requests",
		"cause", context.Cause(ctx).Error(), "timeout", s.shutdownTimeout.String())
	// The parent ctx is already canceled; the drain gets a fresh deadline.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.shutdownTimeout)
	defer cancel()
	if err := s.srv.Shutdown(shutdownCtx); err != nil {
		closeErr := s.srv.Close()
		return fmt.Errorf("graceful shutdown did not finish in %s: %w", s.shutdownTimeout, errors.Join(err, closeErr))
	}
	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	s.logger.InfoContext(ctx, "http server stopped")
	return nil
}
