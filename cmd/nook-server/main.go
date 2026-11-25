// Command nook-server runs the Nook control plane: the REST API used by the
// CLI and dashboard, backed by PostgreSQL and Redis.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/logging"
	"github.com/the-asmit/nook/internal/server"
	"github.com/the-asmit/nook/internal/server/api"
	"github.com/the-asmit/nook/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], config.OSEnviron(), os.Stdout, os.Stderr))
}

// run returns the process exit code: 0 on clean shutdown, 1 on runtime
// failure, 2 on invalid usage or configuration.
func run(args []string, environ map[string]string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "registry-cert" {
		return runRegistryCert(args[1:], environ, stdout, stderr)
	}
	flags := flag.NewFlagSet(server.ServiceName, flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print version information and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	info := version.Get()
	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "%s %s\n", server.ServiceName, info)
		return 0
	}

	cfg, err := config.Load[server.Config](environ)
	if err != nil {
		// The configured logger needs the configuration, so report this
		// failure with a default JSON logger on stderr.
		slog.New(slog.NewJSONHandler(stderr, nil)).Error("invalid configuration",
			"service", server.ServiceName, "problems", config.Problems(err))
		return 2
	}

	logger, err := logging.New(stdout, cfg.Log,
		slog.String("service", server.ServiceName),
		slog.String("version", info.Version),
		slog.String("env", string(cfg.Environment)),
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", server.ServiceName, err)
		return 2
	}
	api.ConfigureGin(cfg.Environment, logger)
	logger.Info("starting", "commit", info.Commit, "build_date", info.BuildDate, "go_version", info.GoVersion,
		"http_addr", cfg.HTTP.Addr, "log_level", cfg.Log.Level)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// After the first signal, restore default handling so a second Ctrl-C
	// kills the process immediately instead of waiting for the drain.
	context.AfterFunc(ctx, stop)

	srv, err := server.New(ctx, &cfg, logger)
	if err != nil {
		logger.Error("startup failed", "error", err.Error())
		return 1
	}
	serveErr := srv.Serve(ctx)
	srv.Close()
	if serveErr != nil {
		logger.Error("shutdown with error", "error", serveErr.Error())
		return 1
	}
	logger.Info("shutdown complete")
	return 0
}
