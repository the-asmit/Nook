package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type workspaceInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Personal  bool      `json:"personal"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type listPage[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// fetchAll follows next_cursor until every page is read.
func fetchAll[T any](cmd *cobra.Command, c *client, path string) ([]T, error) {
	var all []T
	cursor := ""
	for range 1000 {
		p := path + "?limit=100"
		if cursor != "" {
			p += "&cursor=" + url.QueryEscape(cursor)
		}
		var page listPage[T]
		if err := c.do(cmd.Context(), http.MethodGet, p, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.NextCursor == nil {
			return all, nil
		}
		cursor = *page.NextCursor
	}
	return nil, errors.New("too many pages")
}

func (r *runner) table(header string, rows func(w *tabwriter.Writer)) {
	w := tabwriter.NewWriter(r.app.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, header)
	rows(w)
	_ = w.Flush()
}

func (r *runner) workspaceCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "workspace", Short: "List, create and select workspaces"}

	list := &cobra.Command{
		Use: "list", Short: "List your workspaces", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			items, err := fetchAll[workspaceInfo](cmd, c, "/api/v1/workspaces")
			if err != nil {
				return err
			}
			return r.emit(items, func() {
				r.table("\tSLUG\tNAME\tROLE", func(w *tabwriter.Writer) {
					for _, ws := range items {
						mark := ""
						if ws.Slug == s.cfg.Workspace {
							mark = "*"
						}
						_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", mark, ws.Slug, ws.Name, ws.Role)
					}
				})
			})
		},
	}

	var name string
	create := &cobra.Command{
		Use: "create <slug>", Short: "Create a workspace you own", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			if name == "" {
				name = args[0]
			}
			var ws workspaceInfo
			if err := c.do(cmd.Context(), http.MethodPost, "/api/v1/workspaces", map[string]string{"name": name, "slug": args[0]}, &ws); err != nil {
				return err
			}
			return r.emit(ws, func() { r.printf("Created workspace %s (%s).\n", ws.Slug, ws.Name) })
		},
	}
	create.Flags().StringVar(&name, "name", "", "display name (default: the slug)")

	use := &cobra.Command{
		Use: "use <slug>", Short: "Make a workspace the default for later commands", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			var ws workspaceInfo
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/workspaces/"+url.PathEscape(args[0]), nil, &ws); err != nil {
				return err
			}
			s.cfg.Workspace = ws.Slug
			if err := saveConfig(s.dir, s.cfg); err != nil {
				return err
			}
			return r.emit(ws, func() { r.printf("Now using workspace %s.\n", ws.Slug) })
		},
	}
	cmd.AddCommand(list, create, use)
	return cmd
}

type createdToken struct {
	Token    string    `json:"token"`
	Metadata tokenInfo `json:"metadata"`
}

func (r *runner) tokenCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage API tokens for scripts and CI"}

	list := &cobra.Command{
		Use: "list", Short: "List your API tokens (never shows the secrets)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			items, err := fetchAll[tokenInfo](cmd, c, "/api/v1/tokens")
			if err != nil {
				return err
			}
			return r.emit(items, func() {
				r.table("ID\tNAME\tPREFIX\tLAST USED\tEXPIRES", func(w *tabwriter.Writer) {
					for _, t := range items {
						_, _ = fmt.Fprintf(w, "%s\t%s\t%s…\t%s\t%s\n", t.ID, t.Name, t.Prefix, when(t.LastUsedAt), when(t.ExpiresAt))
					}
				})
			})
		},
	}

	var name string
	var days int
	create := &cobra.Command{
		Use: "create", Short: "Create an API token (shown once)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			if name == "" {
				return &usageError{errors.New("--name is required")}
			}
			body := map[string]any{"name": name}
			if days > 0 {
				body["expires_in_days"] = days
			}
			var created createdToken
			if err := c.do(cmd.Context(), http.MethodPost, "/api/v1/tokens", body, &created); err != nil {
				return err
			}
			return r.emit(created, func() {
				r.printf("%s\n", created.Token)
				_, _ = fmt.Fprintf(r.app.Stderr, "Token %q created (id %s). Copy it now: it will not be shown again.\n",
					created.Metadata.Name, created.Metadata.ID)
			})
		},
	}
	create.Flags().StringVar(&name, "name", "", "token name, e.g. \"github-actions\" (required)")
	create.Flags().IntVar(&days, "expires-in-days", 0, "expire after this many days (1-366; default: never)")

	revoke := &cobra.Command{
		Use: "revoke <token-id>", Short: "Revoke one of your API tokens", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			if err := c.do(cmd.Context(), http.MethodDelete, "/api/v1/tokens/"+url.PathEscape(args[0]), nil, nil); err != nil {
				return err
			}
			return r.emit(map[string]any{"revoked": args[0]}, func() { r.printf("Revoked token %s.\n", args[0]) })
		},
	}
	cmd.AddCommand(list, create, revoke)
	return cmd
}

func when(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}
