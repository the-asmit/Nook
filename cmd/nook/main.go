// Command nook is the Nook command-line tool.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/the-asmit/nook/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, &cli.App{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Getenv:      os.Getenv,
		OpenBrowser: cli.OpenBrowser,
	}, os.Args[1:])
	stop()
	os.Exit(code)
}
