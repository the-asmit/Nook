// Command nook-agent runs on every Nook worker node. `nook-agent join`
// enrolls the machine once; `nook-agent run` keeps it connected to the
// control plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/the-asmit/nook/internal/agent"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/platform/config"
	"github.com/the-asmit/nook/internal/platform/logging"
	"github.com/the-asmit/nook/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], config.OSEnviron(), os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run returns the exit code: 0 on success, 1 on failure, 2 on bad usage.
func run(ctx context.Context, args []string, environ map[string]string, stdout, stderr io.Writer) int {
	root := &cobra.Command{Use: "nook-agent", Short: "Nook worker node agent", SilenceUsage: true, SilenceErrors: true}
	var showVersion bool
	root.Flags().BoolVar(&showVersion, "version", false, "print version information and exit")
	root.RunE = func(cmd *cobra.Command, _ []string) error {
		if showVersion {
			_, _ = fmt.Fprintf(stdout, "nook-agent %s\n", version.Get())
			return nil
		}
		return cmd.Help()
	}
	root.AddCommand(joinCommand(environ, stdout), runCommand(environ, stdout), firewallCommand(environ, stdout), &cobra.Command{ //nolint:contextcheck // Cobra hands ctx to every command through ExecuteContext/cmd.Context().
		Use: "version", Short: "Print version information", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, _ = fmt.Fprintf(stdout, "nook-agent %s\n", version.Get())
			return nil
		},
	})
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "nook-agent: %v\n", err)
		var usage usageError
		if errors.As(err, &usage) {
			return 2
		}
		return 1
	}
	return 0
}

type usageError struct{ error }

func newLogger(environ map[string]string, w io.Writer) (*slog.Logger, error) {
	level := environ["NOOK_LOG_LEVEL"]
	if level == "" {
		level = "info"
	}
	return logging.New(w, logging.Config{Level: level}, slog.String("service", "nook-agent"), slog.String("version", version.Get().Version))
}

func joinCommand(environ map[string]string, stdout io.Writer) *cobra.Command {
	var opts agent.JoinOptions
	var labels string
	cmd := &cobra.Command{
		Use:   "join --server <host:port> --token <token> --ca-hash sha256:<hex>",
		Short: "Join this machine to a Nook installation",
		Long: "Enrolls this machine as a worker node. Get the exact command from " +
			"`nook node join-token create`. The token may also be given in NOOK_JOIN_TOKEN " +
			"to keep it out of the process list.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.Token == "" {
				opts.Token = environ["NOOK_JOIN_TOKEN"]
			}
			if opts.Server == "" || opts.Token == "" || opts.CAHash == "" {
				return usageError{errors.New("--server, --token (or NOOK_JOIN_TOKEN) and --ca-hash are required")}
			}
			parsed, err := nodes.ParseLabels(labels)
			if err != nil {
				return usageError{err}
			}
			opts.Labels = parsed
			logger, err := newLogger(environ, os.Stderr)
			if err != nil {
				return usageError{err}
			}
			res, err := agent.Join(cmd.Context(), &opts, logger)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "Joined as node %q (%s). Start the agent with: nook-agent run\n", res.Name, res.NodeID)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.Server, "server", "", "control-plane gRPC address, host:port")
	cmd.Flags().StringVar(&opts.Token, "token", "", "join token (nook_join_...)")
	cmd.Flags().StringVar(&opts.CAHash, "ca-hash", "", "expected CA fingerprint, sha256:<hex>")
	cmd.Flags().StringVar(&opts.Name, "name", "", "node name (default: derived from the hostname)")
	cmd.Flags().StringVar(&labels, "labels", "", "node labels, k=v,k2=v2")
	cmd.Flags().StringVar(&opts.StateDir, "state-dir", stateDirDefault(environ), "directory for the node identity")
	return cmd
}

func stateDirDefault(environ map[string]string) string {
	if d := environ["NOOK_AGENT_STATE_DIR"]; d != "" {
		return d
	}
	return "/var/lib/nook-agent"
}

func runCommand(environ map[string]string, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use: "run", Short: "Run the agent (keeps the node connected to the control plane)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load[agent.Config](environ)
			if err != nil {
				return usageError{fmt.Errorf("invalid configuration: %w", err)}
			}
			logger, err := logging.New(stdout, cfg.Log, slog.String("service", "nook-agent"), slog.String("version", version.Get().Version))
			if err != nil {
				return usageError{err}
			}
			a, err := agent.New(&cfg, logger)
			if err != nil {
				return err
			}
			defer func() { _ = a.Close() }()
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			healthErr := make(chan error, 1)
			go func() { healthErr <- a.ServeHealth(ctx, logger) }()
			runErr := a.Run(ctx)
			cancel()
			if err := <-healthErr; err != nil && runErr == nil {
				runErr = err
			}
			if runErr != nil {
				return runErr
			}
			logger.Info("agent stopped")
			return nil
		},
	}
}

// firewallCommand shows or removes the egress firewall the agent installs.
func firewallCommand(environ map[string]string, stdout io.Writer) *cobra.Command {
	fw := &cobra.Command{Use: "firewall", Short: "Show or remove the egress firewall for app and build containers"}
	load := func() (agent.Config, error) {
		cfg, err := config.Load[agent.Config](environ)
		if err != nil {
			return cfg, usageError{fmt.Errorf("invalid configuration: %w", err)}
		}
		return cfg, nil
	}
	fw.AddCommand(&cobra.Command{
		Use: "rules", Short: "Print the iptables rules the agent installs", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			rules, err := agent.FirewallRules(cmd.Context(), &cfg)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprint(stdout, rules)
			return nil
		},
	}, &cobra.Command{
		Use: "remove", Short: "Remove the egress rules from this node (when it leaves Nook)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := load()
			if err != nil {
				return err
			}
			logger, err := logging.New(stdout, cfg.Log, slog.String("service", "nook-agent"), slog.String("version", version.Get().Version))
			if err != nil {
				return usageError{err}
			}
			if err := agent.RemoveFirewall(cmd.Context(), &cfg, logger); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, "egress firewall removed")
			return nil
		},
	})
	return fw
}
