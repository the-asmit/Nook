// Command nook-gateway is Nook's only public entry point: it serves every
// app at https://<app>--<workspace>.<apps domain>, signs visitors in
// through the auth host and enforces each app's access policy.
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

	"github.com/the-asmit/nook/internal/gateway"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/logging"
	"github.com/the-asmit/nook/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], config.OSEnviron(), os.Stdout, os.Stderr))
}

// run returns the exit code: 0 on clean shutdown, 1 on runtime failure, 2
// on invalid usage or configuration.
func run(args []string, environ map[string]string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(gateway.ServiceName, flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print version information and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	info := version.Get()
	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "%s %s\n", gateway.ServiceName, info)
		return 0
	}
	cfg, err := config.Load[gateway.Config](environ)
	if err != nil {
		slog.New(slog.NewJSONHandler(stderr, nil)).Error("invalid configuration",
			"service", gateway.ServiceName, "problems", config.Problems(err))
		return 2
	}
	logger, err := logging.New(stdout, cfg.Log, slog.String("service", gateway.ServiceName), slog.String("version", info.Version))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", gateway.ServiceName, err)
		return 2
	}
	logger.Info("starting", "commit", info.Commit, "build_date", info.BuildDate, "tls_mode", cfg.TLSMode, "apps", cfg.AppsBaseURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	context.AfterFunc(ctx, stop)
	g, err := gateway.New(ctx, &cfg, logger)
	if err != nil {
		logger.Error("startup failed", "error", err.Error())
		return 1
	}
	defer g.Close()
	if err := g.Serve(ctx); err != nil {
		logger.Error("shutdown with error", "error", err.Error())
		return 1
	}
	logger.Info("shutdown complete")
	return 0
}
