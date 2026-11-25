// Package cli implements the `nook` command-line tool: signing in to a
// Nook server with the device flow and managing workspaces and API tokens
// through the REST API.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/the-asmit/nook/internal/version"
)

// App carries the CLI's input/output and environment, so commands can be
// run in tests without touching the real terminal or home directory.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// OpenBrowser tries to open a URL in the user's browser.
	OpenBrowser func(url string) error
}

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// Output formats.
const (
	outputText = "text"
	outputJSON = "json"
)

type runner struct {
	app           *App
	output        string
	serverFlag    string
	workspaceFlag string
}

// Execute runs the CLI with args and returns the process exit code.
func Execute(ctx context.Context, app *App, args []string) int {
	r := &runner{app: app}
	root := r.rootCommand() //nolint:contextcheck // Cobra hands ctx to every command through ExecuteContext/cmd.Context().
	root.SetArgs(args)
	root.SetOut(app.Stdout)
	root.SetErr(app.Stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	var usage *usageError
	if errors.As(err, &usage) {
		_, _ = fmt.Fprintf(app.Stderr, "error: %v\nRun 'nook --help' for usage.\n", err)
		return exitUsage
	}
	_, _ = fmt.Fprintf(app.Stderr, "error: %v\n", err)
	return exitError
}

// usageError marks mistakes in how the command was invoked.
type usageError struct{ err error }

func (u *usageError) Error() string { return u.err.Error() }

func (r *runner) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "nook",
		Short:         "Deploy and share internal tools on your Nook server",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			if r.output != outputText && r.output != outputJSON {
				return &usageError{fmt.Errorf("--output must be %q or %q", outputText, outputJSON)}
			}
			return nil
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &usageError{err} })
	root.PersistentFlags().StringVarP(&r.output, "output", "o", outputText, "output format: text or json")
	root.PersistentFlags().StringVar(&r.serverFlag, "server", "", "Nook server URL (overrides NOOK_SERVER and the saved login)")
	root.PersistentFlags().StringVarP(&r.workspaceFlag, "workspace", "w", "",
		"workspace slug (overrides NOOK_WORKSPACE, nook.toml and 'nook workspace use')")
	root.AddCommand(
		r.loginCommand(), r.logoutCommand(), r.whoamiCommand(),
		r.workspaceCommand(), r.tokenCommand(), r.versionCommand(),
		r.nodeCommand(), r.adminCommand(),
		r.initCommand(), r.appsCommand(), r.deployCommand(), r.deploymentsCommand(), r.buildLogsCommand(),
	)
	return root
}

// session is the resolved configuration for one command.
type session struct {
	dir    string
	cfg    Config
	server string
	// token is the credential in use; tokenFromEnv says it came from NOOK_TOKEN.
	token        string
	tokenFromEnv bool
}

// load resolves server and token: flags, then NOOK_SERVER/NOOK_TOKEN
// (for CI), then the saved login.
func (r *runner) load() (*session, error) {
	dir, err := configDir(r.app.Getenv)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(dir)
	if err != nil {
		return nil, err
	}
	s := &session{dir: dir, cfg: cfg, server: cfg.Server, token: cfg.Token}
	if v := r.app.Getenv("NOOK_SERVER"); v != "" {
		s.server = v
	}
	if r.serverFlag != "" {
		s.server = r.serverFlag
	}
	if v := r.app.Getenv("NOOK_TOKEN"); v != "" {
		s.token, s.tokenFromEnv = v, true
	}
	return s, nil
}

// authed returns an API client for a command that needs a login.
func (r *runner) authed() (*session, *client, error) {
	s, err := r.load()
	if err != nil {
		return nil, nil, err
	}
	if s.server == "" || s.token == "" {
		return nil, nil, errors.New("not logged in; run 'nook login <server-url>' (or set NOOK_SERVER and NOOK_TOKEN)")
	}
	c, err := newClient(s.server, s.token, userAgent())
	if err != nil {
		return nil, nil, err
	}
	return s, c, nil
}

func userAgent() string {
	return "nook-cli/" + version.Get().Version
}

// printJSON writes v as indented JSON.
func (r *runner) printJSON(v any) error {
	enc := json.NewEncoder(r.app.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// printf writes human-readable output.
func (r *runner) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(r.app.Stdout, format, args...)
}

// emit prints v as JSON, or calls text for the human format.
func (r *runner) emit(v any, text func()) error {
	if r.output == outputJSON {
		return r.printJSON(v)
	}
	text()
	return nil
}

func (r *runner) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			info := version.Get()
			return r.emit(info, func() { r.printf("nook %s\n", info) })
		},
	}
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
