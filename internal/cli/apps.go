package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type appInfo struct {
	ID              string    `json:"id"`
	Slug            string    `json:"slug"`
	Name            string    `json:"name"`
	Port            int32     `json:"port"`
	HealthCheckPath string    `json:"health_check_path"`
	MemoryMB        int32     `json:"memory_mb"`
	CPUMillicores   int32     `json:"cpu_millicores"`
	Deployments     int32     `json:"deployments"`
	CreatedAt       time.Time `json:"created_at"`
}

// workspaceFor picks the workspace: --workspace, then NOOK_WORKSPACE, then
// nook.toml's workspace (if a project is given), then the saved default.
func (r *runner) workspaceFor(s *session, p *Project) (string, error) {
	switch {
	case r.workspaceFlag != "":
		return r.workspaceFlag, nil
	case r.app.Getenv("NOOK_WORKSPACE") != "":
		return r.app.Getenv("NOOK_WORKSPACE"), nil
	case p != nil && p.Workspace != "":
		return p.Workspace, nil
	case s.cfg.Workspace != "":
		return s.cfg.Workspace, nil
	}
	return "", errors.New("no workspace selected; use --workspace, set workspace in nook.toml, or run 'nook workspace use <slug>'")
}

func appsPath(ws string) string { return "/api/v1/workspaces/" + url.PathEscape(ws) + "/apps" }

func appPath(ws, app string) string { return appsPath(ws) + "/" + url.PathEscape(app) }

// optionalProject loads nook.toml from the current folder if there is one.
func optionalProject() (*Project, error) {
	p, err := loadProject(".")
	if errors.Is(err, errNoProject) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *runner) initCommand() *cobra.Command {
	p := defaultProject("")
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write nook.toml for the project in the current folder",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if p.App == "" {
				p.App = slugFromDir(".")
			}
			// --workspace pins the workspace in the file.
			p.Workspace = r.workspaceFlag
			if _, err := os.Stat(ProjectFile); err == nil && !force {
				return &usageError{fmt.Errorf("%s already exists; use --force to overwrite it", ProjectFile)}
			}
			if err := writeProject(".", &p); err != nil {
				return &usageError{err}
			}
			return r.emit(p, func() {
				r.printf("Wrote %s for app %q (port %d, health check %s).\nNext: nook deploy\n", ProjectFile, p.App, p.Port, p.HealthCheckPath)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&p.App, "app", "", "app slug (default: derived from the folder name)")
	f.Int32Var(&p.Port, "port", p.Port, "port the app listens on")
	f.StringVar(&p.HealthCheckPath, "health-check-path", p.HealthCheckPath, "path that answers 2xx when the app is healthy")
	f.Int32Var(&p.MemoryMB, "memory", p.MemoryMB, "memory limit in MB")
	f.Int32Var(&p.CPUMillicores, "cpu", p.CPUMillicores, "CPU limit in millicores (1000 = one CPU)")
	f.BoolVar(&force, "force", false, "overwrite an existing nook.toml")
	return cmd
}

func (r *runner) appsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "apps", Short: "Create, list, inspect and delete apps"}

	create := &cobra.Command{
		Use: "create [slug]", Short: "Create an app (settings from nook.toml when present)", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			p, err := optionalProject()
			if err != nil {
				return err
			}
			spec := defaultProject("")
			if p != nil {
				spec = *p
			}
			if len(args) == 1 {
				spec.App = args[0]
			}
			if spec.App == "" {
				return &usageError{errors.New("give the app slug, or run 'nook init' first")}
			}
			ws, err := r.workspaceFor(s, p)
			if err != nil {
				return err
			}
			app, err := createApp(cmd, c, ws, &spec)
			if err != nil {
				return err
			}
			return r.emit(app, func() { r.printf("Created app %s in workspace %s.\n", app.Slug, ws) })
		},
	}

	list := &cobra.Command{
		Use: "list", Short: "List the workspace's apps", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			p, err := optionalProject()
			if err != nil {
				return err
			}
			ws, err := r.workspaceFor(s, p)
			if err != nil {
				return err
			}
			items, err := fetchAll[appInfo](cmd, c, appsPath(ws))
			if err != nil {
				return err
			}
			return r.emit(items, func() {
				r.table("APP\tNAME\tPORT\tMEMORY\tCPU\tDEPLOYMENTS\tCREATED", func(w *tabwriter.Writer) {
					for _, a := range items {
						_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%d MB\t%dm\t%d\t%s\n", a.Slug, a.Name, a.Port, a.MemoryMB, a.CPUMillicores,
							a.Deployments, a.CreatedAt.Local().Format("2006-01-02 15:04"))
					}
				})
			})
		},
	}

	info := &cobra.Command{
		Use: "info <slug>", Short: "Show an app and its latest deployment", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			p, err := optionalProject()
			if err != nil {
				return err
			}
			ws, err := r.workspaceFor(s, p)
			if err != nil {
				return err
			}
			var app appInfo
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
			return r.emit(map[string]any{"app": app, "latest_deployment": latest}, func() {
				r.printf("App:          %s (%s)\nWorkspace:    %s\nPort:         %d\nHealth check: %s\nLimits:       %d MB, %d millicores\nCreated:      %s\n",
					app.Slug, app.Name, ws, app.Port, app.HealthCheckPath, app.MemoryMB, app.CPUMillicores, app.CreatedAt.Local().Format(time.RFC1123))
				if latest == nil {
					r.printf("Deployments:  none yet (run 'nook deploy')\n")
					return
				}
				r.printf("Latest:       #%d %s", latest.Number, latest.Status)
				if latest.Image != nil {
					r.printf(" %s", *latest.Image)
				}
				r.printf("\n")
			})
		},
	}

	var yes bool
	del := &cobra.Command{
		Use: "delete <slug>", Short: "Delete an app with its images and history (workspace admins)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return &usageError{fmt.Errorf("deleting %s removes its images and build history; repeat with --yes to confirm", args[0])}
			}
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			p, err := optionalProject()
			if err != nil {
				return err
			}
			ws, err := r.workspaceFor(s, p)
			if err != nil {
				return err
			}
			if err := c.do(cmd.Context(), http.MethodDelete, appPath(ws, args[0]), nil, nil); err != nil {
				return err
			}
			return r.emit(map[string]string{"app": args[0], "result": "deleted"}, func() { r.printf("Deleted app %s.\n", args[0]) })
		},
	}
	del.Flags().BoolVar(&yes, "yes", false, "confirm the deletion")

	cmd.AddCommand(create, list, info, del)
	return cmd
}

func createApp(cmd *cobra.Command, c *client, ws string, p *Project) (appInfo, error) {
	var app appInfo
	err := c.do(cmd.Context(), http.MethodPost, appsPath(ws), map[string]any{
		"slug": p.App, "port": p.Port, "health_check_path": p.HealthCheckPath,
		"memory_mb": p.MemoryMB, "cpu_millicores": p.CPUMillicores,
	}, &app)
	return app, err
}
