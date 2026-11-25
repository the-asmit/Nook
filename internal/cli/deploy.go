package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/the-asmit/nook/internal/archive"
)

type buildInfo struct {
	Attempt    int32      `json:"attempt"`
	Node       string     `json:"node"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Result     *string    `json:"result"`
	Message    string     `json:"message"`
}

type deploymentInfo struct {
	Number          int32       `json:"number"`
	Status          string      `json:"status"`
	SourceSize      int64       `json:"source_size"`
	ImageDigest     *string     `json:"image_digest"`
	Image           *string     `json:"image"`
	FailureReason   string      `json:"failure_reason"`
	CancelRequested bool        `json:"cancel_requested"`
	CreatedAt       time.Time   `json:"created_at"`
	BuiltAt         *time.Time  `json:"built_at"`
	ImageDeleted    bool        `json:"image_deleted"`
	Builds          []buildInfo `json:"builds"`
	// Kind is build, config (new environment) or rollback.
	Kind       string        `json:"kind"`
	RollbackTo *int32        `json:"rollback_to"`
	LiveAt     *time.Time    `json:"live_at"`
	Instance   *instanceInfo `json:"instance"`
}

type createDeploymentResult struct {
	Deployment deploymentInfo `json:"deployment"`
	Upload     struct {
		URL       string            `json:"url"`
		Method    string            `json:"method"`
		Headers   map[string]string `json:"headers"`
		ExpiresAt time.Time         `json:"expires_at"`
	} `json:"upload"`
	MaxSourceBytes int64 `json:"max_source_bytes"`
}

// defaultMaxSource is the client-side archive limit (the server enforces
// its own, configurable limit too).
const defaultMaxSource = 200 << 20

// errDeployFailed makes `nook deploy` exit non-zero after printing why.
var errDeployFailed = errors.New("the deployment did not go live")

func (r *runner) deployCommand() *cobra.Command {
	var appFlag, dir string
	var noFollow bool
	var maxSize int64
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Package the project, build its image and release it",
		Long: "Packages the folder (honoring .dockerignore and .nookignore), uploads it straight to storage,\n" +
			"queues a build, then follows the build and the rollout until the new version is live (it passes\n" +
			"its health check and replaces the previous one). Exits non-zero if the build or the release fails;\n" +
			"a failed release leaves the previous version serving.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			p, err := loadProject(dir)
			if err != nil && (!errors.Is(err, errNoProject) || appFlag == "") {
				return err
			}
			if appFlag != "" {
				p.App = appFlag
			}
			ws, err := r.workspaceFor(s, &p)
			if err != nil {
				return err
			}
			if appErr := r.ensureApp(cmd, c, ws, &p); appErr != nil {
				return appErr
			}
			d, err := r.uploadSource(cmd.Context(), c, s, ws, p.App, dir, maxSize)
			if err != nil {
				return err
			}
			if noFollow {
				return r.emit(d, func() {
					r.printf("Deployment #%d of %s is %s. Follow it with: nook build-logs %s %d --follow\n", d.Number, p.App, d.Status, p.App, d.Number)
				})
			}
			return r.followDeployment(cmd.Context(), c, ws, p.App, d.Number, d.Status)
		},
	}
	f := cmd.Flags()
	f.StringVar(&appFlag, "app", "", "app slug (default: app in nook.toml)")
	f.StringVar(&dir, "dir", ".", "project folder")
	f.BoolVar(&noFollow, "no-follow", false, "return once the build is queued")
	f.Int64Var(&maxSize, "max-size", defaultMaxSource, "largest source archive to upload, in bytes")
	return cmd
}

// ensureApp creates the app on first deploy when nook.toml describes it,
// and otherwise brings its settings in line with nook.toml.
func (r *runner) ensureApp(cmd *cobra.Command, c *client, ws string, p *Project) error {
	var app appInfo
	err := c.do(cmd.Context(), http.MethodGet, appPath(ws, p.App), nil, &app)
	if err == nil {
		return r.syncSettings(cmd, c, ws, p, &app)
	}
	if !isAPIError(err, "not_found") {
		return err
	}
	if p.Port == 0 {
		return fmt.Errorf("app %s does not exist in workspace %s; create it with 'nook apps create %s'", p.App, ws, p.App)
	}
	if _, err := createApp(cmd, c, ws, p); err != nil {
		return err
	}
	r.status("Created app %s in workspace %s.", p.App, ws)
	return nil
}

// syncSettings updates the app's settings that nook.toml changed.
func (r *runner) syncSettings(cmd *cobra.Command, c *client, ws string, p *Project, app *appInfo) error {
	if p.Port == 0 { // no nook.toml (deploy --app)
		return nil
	}
	changes := map[string]any{}
	if p.Port != app.Port {
		changes["port"] = p.Port
	}
	if p.HealthCheckPath != app.HealthCheckPath {
		changes["health_check_path"] = p.HealthCheckPath
	}
	if p.MemoryMB != app.MemoryMB {
		changes["memory_mb"] = p.MemoryMB
	}
	if p.CPUMillicores != app.CPUMillicores {
		changes["cpu_millicores"] = p.CPUMillicores
	}
	if p.StartupTimeout != app.StartupTimeoutSeconds {
		changes["startup_timeout_seconds"] = p.StartupTimeout
	}
	if p.ReadOnlyRootfs != app.ReadOnlyRootfs {
		changes["read_only_rootfs"] = p.ReadOnlyRootfs
	}
	if len(changes) == 0 {
		return nil
	}
	if err := c.do(cmd.Context(), http.MethodPatch, appPath(ws, p.App), changes, nil); err != nil {
		return err
	}
	r.status("Updated the settings of %s from %s.", p.App, ProjectFile)
	return nil
}

// uploadSource packs dir, creates the deployment, uploads the archive with
// the presigned URL and confirms the upload.
func (r *runner) uploadSource(ctx context.Context, c *client, s *session, ws, app, dir string, maxSize int64) (deploymentInfo, error) {
	tmp, err := os.CreateTemp("", "nook-source-*.tar.gz")
	if err != nil {
		return deploymentInfo{}, fmt.Errorf("create temporary file: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	lastReport := time.Time{}
	res, err := archive.Pack(dir, tmp, archive.PackOptions{
		MaxBytes:     maxSize,
		ExcludeFiles: []string{filepath.Join(s.dir, configFileName)},
		Progress: func(files int, bytes int64) {
			if time.Since(lastReport) > 500*time.Millisecond {
				lastReport = time.Now()
				r.status("Packing… %d files, %s", files, bytesHuman(bytes))
			}
		},
	})
	if errors.Is(err, archive.ErrTooLarge) {
		return deploymentInfo{}, fmt.Errorf("the source archive is larger than %s; exclude build output and dependencies in .dockerignore or .nookignore", bytesHuman(maxSize))
	}
	if err != nil {
		return deploymentInfo{}, err
	}
	r.status("Packed %d files into %s (sha256 %s).", res.Files, bytesHuman(res.Size), hex.EncodeToString(res.SHA256)[:12])

	var created createDeploymentResult
	if err := c.do(ctx, http.MethodPost, appPath(ws, app)+"/deployments", map[string]any{
		"source_size": res.Size, "source_sha256": hex.EncodeToString(res.SHA256),
	}, &created); err != nil {
		return deploymentInfo{}, err
	}
	n := created.Deployment.Number
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return deploymentInfo{}, fmt.Errorf("rewind archive: %w", err)
	}
	if err := r.put(ctx, &created, tmp, res.Size); err != nil {
		return deploymentInfo{}, err
	}
	var d deploymentInfo
	if err := c.do(ctx, http.MethodPost, appPath(ws, app)+"/deployments/"+strconv.Itoa(int(n))+"/upload-complete", nil, &d); err != nil {
		return deploymentInfo{}, err
	}
	r.status("Deployment #%d %s.", d.Number, d.Status)
	return d, nil
}

// put uploads the archive to storage. It uses its own HTTP client: the
// Nook API token must never be sent to the storage service, and the
// presigned URL (a credential) is never printed.
func (r *runner) put(ctx context.Context, created *createDeploymentResult, body io.Reader, size int64) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	pr := &progressReader{r: body, total: size, report: func(done int64) {
		r.status("Uploading… %d%% of %s", done*100/max(size, 1), bytesHuman(size))
	}}
	req, err := http.NewRequestWithContext(ctx, created.Upload.Method, created.Upload.URL, pr)
	if err != nil {
		return errors.New("the server returned an invalid upload URL")
	}
	req.ContentLength = size
	for k, v := range created.Upload.Headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return fmt.Errorf("upload the source archive: %w", unwrapURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload the source archive: storage answered HTTP %d", resp.StatusCode)
	}
	r.status("Uploaded %s.", bytesHuman(size))
	return nil
}

// followDeployment streams the deployment's log (build, then rollout) and
// returns errDeployFailed unless the deployment goes live.
// shown is the status already printed (it is not repeated).
func (r *runner) followDeployment(ctx context.Context, c *client, ws, app string, n int32, shown string) error {
	path := appPath(ws, app) + "/deployments/" + strconv.Itoa(int(n)) + "/build-log?follow=1"
	var final deploymentInfo
	err := c.stream(ctx, path, func(event string, data []byte) error {
		switch event {
		case "line":
			var l struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(data, &l) == nil && r.output != outputJSON {
				r.printf("%s\n", l.Text)
			}
		case "status":
			var st struct {
				Status string `json:"status"`
			}
			if json.Unmarshal(data, &st) == nil && st.Status != shown {
				shown = st.Status
				r.status("Deployment #%d is %s.", n, st.Status)
			}
		case "end":
			if err := json.Unmarshal(data, &final); err != nil {
				return fmt.Errorf("decode the final status: %w", err)
			}
			return errStreamDone
		}
		return nil
	})
	if errors.Is(err, context.Canceled) {
		r.status("Stopped following; the deployment continues. Check it with: nook apps info %s", app)
		return err
	}
	if err != nil {
		return err
	}
	if err := r.emit(final, func() {
		switch final.Status {
		case "live":
			r.printf("\nDeployment #%d of %s is live.\n", final.Number, app)
			if final.Image != nil {
				r.printf("Image: %s\n", *final.Image)
			}
			if u := final.Instance.URL(); u != "" {
				r.printf("Node:  %s, serving at %s (reachable on the node's network)\n", final.Instance.Node, u)
			}
		case "built":
			r.printf("\nBuilt deployment #%d of %s; the app is stopped, so it is released when you run 'nook apps start %s'.\n",
				final.Number, app, app)
		default:
			r.printf("\nDeployment #%d %s: %s\n", final.Number, final.Status, dash(final.FailureReason))
			if final.Image != nil && final.Status == "failed" {
				r.printf("The previous version keeps serving. Logs of the failed start are above.\n")
			}
		}
	}); err != nil {
		return err
	}
	if final.Status != "live" && final.Status != "built" {
		return errDeployFailed
	}
	return nil
}

func (r *runner) deploymentsCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "deployments", Short: "List and cancel an app's deployments"}
	list := &cobra.Command{
		Use: "list <app>", Short: "List an app's deployments, newest first", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			items, err := fetchAll[deploymentInfo](cmd, c, appPath(ws, args[0])+"/deployments")
			if err != nil {
				return err
			}
			return r.emit(items, func() {
				r.table("#\tSTATUS\tCREATED\tSIZE\tIMAGE\tREASON", func(w *tabwriter.Writer) {
					for i := range items {
						d := &items[i]
						img := "-"
						if d.ImageDigest != nil {
							img = (*d.ImageDigest)[:19]
							if d.ImageDeleted {
								img += " (deleted)"
							}
						}
						_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", d.Number, d.Status, d.CreatedAt.Local().Format("2006-01-02 15:04:05"),
							bytesHuman(d.SourceSize), img, dash(d.FailureReason))
					}
				})
			})
		},
	}
	cancelCmd := &cobra.Command{
		Use: "cancel <app> <number>", Short: "Cancel a queued or running deployment", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return &usageError{errors.New("number must be a positive integer")}
			}
			var d deploymentInfo
			if err := c.do(cmd.Context(), http.MethodPost, appPath(ws, args[0])+"/deployments/"+args[1]+"/cancel", nil, &d); err != nil {
				return err
			}
			return r.emit(d, func() {
				if d.Status == "building" {
					r.printf("Canceling deployment #%d; the build stops shortly.\n", d.Number)
					return
				}
				r.printf("Deployment #%d is %s.\n", d.Number, d.Status)
			})
		},
	}
	cmd.AddCommand(list, cancelCmd)
	return cmd
}

func (r *runner) buildLogsCommand() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use: "build-logs <app> [number]", Short: "Show a deployment's build log (default: the latest)", Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var n int
			if len(args) == 2 {
				if n, err = strconv.Atoi(args[1]); err != nil || n < 1 {
					return &usageError{errors.New("number must be a positive integer")}
				}
			} else {
				var app appInfo
				if getErr := c.do(cmd.Context(), http.MethodGet, appPath(ws, args[0]), nil, &app); getErr != nil {
					return getErr
				}
				if app.Deployments == 0 {
					return fmt.Errorf("app %s has no deployments yet", args[0])
				}
				n = int(app.Deployments)
			}
			if follow {
				return r.followDeployment(cmd.Context(), c, ws, args[0], int32(n), "") //nolint:gosec // G115: parsed as a small positive integer.
			}
			text, err := c.text(cmd.Context(), appPath(ws, args[0])+"/deployments/"+strconv.Itoa(n)+"/build-log")
			if err != nil {
				return err
			}
			_, err = io.WriteString(r.app.Stdout, text)
			return err
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow the log until the build ends")
	return cmd
}

// appContext resolves the session's client and workspace for app commands.
func (r *runner) appContext() (string, *client, error) {
	s, c, err := r.authed()
	if err != nil {
		return "", nil, err
	}
	p, err := optionalProject()
	if err != nil {
		return "", nil, err
	}
	ws, err := r.workspaceFor(s, p)
	return ws, c, err
}

// status prints progress to stderr (stdout stays for the log and results).
func (r *runner) status(format string, args ...any) {
	_, _ = fmt.Fprintf(r.app.Stderr, format+"\n", args...)
}

type progressReader struct {
	r      io.Reader
	total  int64
	done   int64
	last   time.Time
	report func(done int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if time.Since(p.last) > time.Second {
		p.last = time.Now()
		p.report(p.done)
	}
	return n, err
}
