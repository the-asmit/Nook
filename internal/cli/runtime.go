package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// instanceInfo is where and how an app instance runs.
type instanceInfo struct {
	Node          string     `json:"node"`
	State         string     `json:"state"`
	Address       string     `json:"address"`
	HostPort      *int32     `json:"host_port"`
	RestartCount  int32      `json:"restart_count"`
	LastError     string     `json:"last_error"`
	StartedAt     *time.Time `json:"started_at"`
	LastHealthyAt *time.Time `json:"last_healthy_at"`
	StartupLog    string     `json:"startup_log"`
}

// URL is the address the node publishes the instance on.
func (i *instanceInfo) URL() string {
	if i == nil || i.HostPort == nil || i.Address == "" {
		return ""
	}
	host := i.Address
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + strconv.Itoa(int(*i.HostPort))
}

// appDetail is an app with what runs it.
type appDetail struct {
	appInfo
	LiveDeployment *int32        `json:"live_deployment"`
	Health         string        `json:"health"`
	Instance       *instanceInfo `json:"instance"`
}

func (r *runner) appsInfoCommand() *cobra.Command {
	return &cobra.Command{
		Use: "info <slug>", Short: "Show an app: desired state, live deployment, instance, node, restarts, last error", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var app appDetail
			if err := c.do(cmd.Context(), http.MethodGet, appPath(ws, args[0]), nil, &app); err != nil {
				return err
			}
			var latest *deploymentInfo
			if app.Deployments > 0 {
				var d deploymentInfo
				if err := c.do(cmd.Context(), http.MethodGet, appPath(ws, app.Slug)+"/deployments/"+strconv.Itoa(int(app.Deployments)), nil, &d); err != nil {
					return err
				}
				latest = &d
			}
			return r.emit(map[string]any{"app": app, "latest_deployment": latest}, func() { r.printAppDetail(ws, &app, latest) })
		},
	}
}

func (r *runner) printAppDetail(ws string, app *appDetail, latest *deploymentInfo) {
	r.printf("App:          %s (%s)\nWorkspace:    %s\nURL:          %s (access: %s)\nDesired:      %s\nHealth:       %s\n",
		app.Slug, app.Name, ws, app.URL, app.AccessMode, app.DesiredState, app.Health)
	if app.LiveDeployment != nil {
		r.printf("Live:         #%d\n", *app.LiveDeployment)
	} else {
		r.printf("Live:         none\n")
	}
	if i := app.Instance; i != nil {
		r.printf("Instance:     %s on node %s", i.State, i.Node)
		if u := i.URL(); u != "" {
			r.printf(" at %s", u)
		}
		r.printf("\nRestarts:     %d\n", i.RestartCount)
		if i.LastError != "" {
			r.printf("Last error:   %s\n", i.LastError)
		}
	}
	r.printf("Port:         %d\nHealth check: %s (startup timeout %ds)\nLimits:       %d MB, %d millicores\nRead-only fs: %t\nCreated:      %s\n",
		app.Port, app.HealthCheckPath, app.StartupTimeoutSeconds, app.MemoryMB, app.CPUMillicores, app.ReadOnlyRootfs,
		app.CreatedAt.Local().Format(time.RFC1123))
	if latest == nil {
		r.printf("Deployments:  none yet (run 'nook deploy')\n")
		return
	}
	r.printf("Latest:       #%d %s", latest.Number, latest.Status)
	if latest.Image != nil {
		r.printf(" %s", *latest.Image)
	}
	r.printf("\n")
}

// lifecycleCommand is `nook apps stop` or `nook apps start`.
func (r *runner) lifecycleCommand(verb, short string) *cobra.Command {
	return &cobra.Command{
		Use: verb + " <slug>", Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var app appDetail
			if err := c.do(cmd.Context(), http.MethodPost, appPath(ws, args[0])+"/"+verb, nil, &app); err != nil {
				return err
			}
			return r.emit(app, func() {
				if verb == "stop" {
					r.printf("Stopping %s; it stays stopped until 'nook apps start %s'.\n", app.Slug, app.Slug)
					return
				}
				r.printf("Starting %s. Check it with 'nook apps info %s'.\n", app.Slug, app.Slug)
			})
		},
	}
}

type envVarInfo struct {
	Key       string    `json:"key"`
	Value     *string   `json:"value"`
	Secret    bool      `json:"secret"`
	UpdatedAt time.Time `json:"updated_at"`
}

type envChangeInfo struct {
	Items      []envVarInfo    `json:"items"`
	Deployment *deploymentInfo `json:"deployment"`
}

func (r *runner) envCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "env", Short: "Manage an app's environment variables and secrets"}
	list := &cobra.Command{
		Use: "list <app>", Short: "List variables (secret values are never shown)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var res struct {
				Items []envVarInfo `json:"items"`
			}
			if err := c.do(cmd.Context(), http.MethodGet, appPath(ws, args[0])+"/env", nil, &res); err != nil {
				return err
			}
			return r.emit(res.Items, func() { r.printEnv(res.Items) })
		},
	}
	var secret, noFollow bool
	set := &cobra.Command{
		Use:   "set <app> KEY=VALUE [KEY=VALUE...]",
		Short: "Set variables and release them (no rebuild); --secret needs a workspace admin",
		Long: "Sets variables and, if the app is live, rolls out a new deployment of the same image with the new\n" +
			"environment. Use --secret for credentials: secret values are encrypted and never shown again.\n" +
			"Give a value as KEY=- to read it from standard input (keeps it out of shell history).",
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			vars, err := r.parseAssignments(args[1:])
			if err != nil {
				return err
			}
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var res envChangeInfo
			if err := c.do(cmd.Context(), http.MethodPut, appPath(ws, args[0])+"/env", map[string]any{"vars": vars, "secret": secret}, &res); err != nil {
				return err
			}
			return r.afterEnvChange(cmd, c, ws, args[0], &res, noFollow)
		},
	}
	set.Flags().BoolVar(&secret, "secret", false, "store the values as secrets (workspace admins and owners)")
	set.Flags().BoolVar(&noFollow, "no-follow", false, "return without waiting for the new deployment")
	unset := &cobra.Command{
		Use: "unset <app> KEY", Short: "Remove a variable and release the change", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var res envChangeInfo
			if err := c.do(cmd.Context(), http.MethodDelete, appPath(ws, args[0])+"/env/"+url.PathEscape(args[1]), nil, &res); err != nil {
				return err
			}
			return r.afterEnvChange(cmd, c, ws, args[0], &res, noFollow)
		},
	}
	unset.Flags().BoolVar(&noFollow, "no-follow", false, "return without waiting for the new deployment")
	cmd.AddCommand(list, set, unset)
	return cmd
}

// parseAssignments reads KEY=VALUE arguments; a value of "-" is read from
// standard input (one value per such key, in order).
func (r *runner) parseAssignments(args []string) (map[string]string, error) {
	vars := map[string]string{}
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			return nil, &usageError{fmt.Errorf("%q is not KEY=VALUE", truncateArg(a))}
		}
		if v == "-" {
			line, err := r.readLine()
			if err != nil {
				return nil, fmt.Errorf("read the value of %s from standard input: %w", k, err)
			}
			v = line
		}
		vars[k] = v
	}
	return vars, nil
}

// truncateArg shows the start of an argument without its value.
func truncateArg(a string) string {
	if k, _, ok := strings.Cut(a, "="); ok {
		return k + "=…"
	}
	if len(a) > 40 {
		return a[:40] + "…"
	}
	return a
}

func (r *runner) readLine() (string, error) {
	if r.app.Stdin == nil {
		return "", errors.New("no standard input")
	}
	var b strings.Builder
	buf := make([]byte, 1)
	for b.Len() <= 32<<10 {
		n, err := r.app.Stdin.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return strings.TrimSuffix(b.String(), "\r"), nil
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			if b.Len() > 0 {
				return b.String(), nil
			}
			return "", err
		}
	}
	return "", errors.New("the value is longer than 32 KiB")
}

func (r *runner) printEnv(items []envVarInfo) {
	if len(items) == 0 {
		r.printf("No variables.\n")
		return
	}
	r.table("KEY\tVALUE\tUPDATED", func(w *tabwriter.Writer) {
		for _, v := range items {
			value := "******** (secret)"
			if v.Value != nil {
				value = *v.Value
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", v.Key, value, v.UpdatedAt.Local().Format("2006-01-02 15:04"))
		}
	})
}

func (r *runner) afterEnvChange(cmd *cobra.Command, c *client, ws, app string, res *envChangeInfo, noFollow bool) error {
	if res.Deployment == nil || noFollow || r.output == outputJSON {
		return r.emit(res, func() {
			r.printEnv(res.Items)
			if res.Deployment != nil {
				r.printf("Releasing the change as deployment #%d.\n", res.Deployment.Number)
				return
			}
			r.printf("The app is not live; the next deployment uses these variables.\n")
		})
	}
	r.status("Releasing the change as deployment #%d (same image, no rebuild).", res.Deployment.Number)
	return r.followDeployment(cmd.Context(), c, ws, app, res.Deployment.Number, res.Deployment.Status)
}

func (r *runner) rollbackCommand() *cobra.Command {
	var to int32
	var noFollow bool
	cmd := &cobra.Command{
		Use:   "rollback <app>",
		Short: "Release an earlier deployment again, with the environment it had",
		Long: "Rolls back to the previous live deployment, or to --to <number>. The image and the environment\n" +
			"snapshot of that deployment are released as a new deployment, with the usual health check.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if to < 0 {
				return &usageError{errors.New("--to must be a deployment number")}
			}
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var d deploymentInfo
			if err := c.do(cmd.Context(), http.MethodPost, appPath(ws, args[0])+"/rollback", map[string]any{"to": to}, &d); err != nil {
				return err
			}
			if noFollow || r.output == outputJSON {
				return r.emit(d, func() { r.printf("Rolling back to #%d as deployment #%d.\n", deref(d.RollbackTo), d.Number) })
			}
			r.status("Rolling back to #%d as deployment #%d.", deref(d.RollbackTo), d.Number)
			return r.followDeployment(cmd.Context(), c, ws, args[0], d.Number, d.Status)
		},
	}
	cmd.Flags().Int32Var(&to, "to", 0, "deployment number to release again (default: the previous live one)")
	cmd.Flags().BoolVar(&noFollow, "no-follow", false, "return without waiting for the rollout")
	return cmd
}

func deref(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func (r *runner) logsCommand() *cobra.Command {
	var follow bool
	var since string
	var tail int
	cmd := &cobra.Command{
		Use: "logs <app>", Short: "Show the app's runtime output", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tail < 0 || tail > 10000 {
				return &usageError{errors.New("--tail must be between 0 and 10000")}
			}
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			q := url.Values{}
			if follow {
				q.Set("follow", "1")
			}
			if since != "" {
				q.Set("since", since)
			}
			q.Set("tail", strconv.Itoa(tail))
			err = c.stream(cmd.Context(), appPath(ws, args[0])+"/logs?"+q.Encode(), func(event string, data []byte) error {
				switch event {
				case "line":
					var l struct {
						Time   time.Time `json:"time"`
						Stream string    `json:"stream"`
						Text   string    `json:"text"`
					}
					if decodeErr := json.Unmarshal(data, &l); decodeErr != nil {
						return fmt.Errorf("decode a log line: %w", decodeErr)
					}
					if r.output == outputJSON {
						r.printf("%s\n", data)
						return nil
					}
					w := r.app.Stdout
					if l.Stream == "stderr" {
						w = r.app.Stderr
					}
					_, _ = fmt.Fprintln(w, l.Text)
				case "end":
					var e struct {
						Reason string `json:"reason"`
					}
					if json.Unmarshal(data, &e) == nil && e.Reason != "" && e.Reason != "end of output" {
						r.status("[nook] %s", e.Reason)
					}
					return errStreamDone
				}
				return nil
			})
			if cmd.Context().Err() != nil {
				return nil //nolint:nilerr // Ctrl-C while following ends the command normally.
			}
			return err
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep streaming new output")
	cmd.Flags().StringVar(&since, "since", "", "only output newer than this (10m, 1h, or an RFC 3339 time)")
	cmd.Flags().IntVar(&tail, "tail", 200, "lines from the end to start with (0: all retained output)")
	return cmd
}
