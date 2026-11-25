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

type adminUser struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Name            string     `json:"name"`
	IsInstanceAdmin bool       `json:"is_instance_admin"`
	LastLoginAt     *time.Time `json:"last_login_at"`
	DisabledAt      *time.Time `json:"disabled_at"`
}

func (r *runner) adminCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "admin", Short: "Instance administration"}
	users := &cobra.Command{Use: "users", Short: "List, disable and enable users"}

	var email string
	list := &cobra.Command{
		Use: "list", Short: "List users", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			path := "/api/v1/admin/users"
			if email != "" {
				path += "?email=" + url.QueryEscape(email)
			}
			items, err := fetchAllWithQuery[adminUser](cmd, c, path)
			if err != nil {
				return err
			}
			return r.emit(items, func() {
				r.table("EMAIL\tNAME\tADMIN\tSTATE\tLAST LOGIN", func(w *tabwriter.Writer) {
					for _, u := range items {
						state := "active"
						if u.DisabledAt != nil {
							state = "disabled"
						}
						_, _ = fmt.Fprintf(w, "%s\t%s\t%v\t%s\t%s\n", u.Email, dash(u.Name), u.IsInstanceAdmin, state, when(u.LastLoginAt))
					}
				})
			})
		},
	}
	list.Flags().StringVar(&email, "email", "", "show only this email address")

	users.AddCommand(list, r.setDisabledCommand(true), r.setDisabledCommand(false))
	cmd.AddCommand(users, r.quotaCommand())
	return cmd
}

type quotaInfo struct {
	MaxApps             int32 `json:"max_apps"`
	MaxConcurrentBuilds int32 `json:"max_concurrent_builds"`
	Default             bool  `json:"default"`
}

func (r *runner) quotaCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "quota", Short: "Show and set a workspace's quota"}
	show := func(ws string, q *quotaInfo) {
		src := "override"
		if q.Default {
			src = "instance default"
		}
		r.printf("Workspace %s: at most %d apps and %d concurrent builds (%s).\n", ws, q.MaxApps, q.MaxConcurrentBuilds, src)
	}
	get := &cobra.Command{
		Use: "get <workspace>", Short: "Show a workspace's quota", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			var q quotaInfo
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/admin/workspaces/"+url.PathEscape(args[0])+"/quota", nil, &q); err != nil {
				return err
			}
			return r.emit(q, func() { show(args[0], &q) })
		},
	}
	var maxApps, maxBuilds int32
	set := &cobra.Command{
		Use: "set <workspace> --max-apps N --max-builds N", Short: "Override a workspace's quota", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if maxApps < 0 || maxBuilds < 0 {
				return &usageError{errors.New("--max-apps and --max-builds are required")}
			}
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			var q quotaInfo
			body := map[string]int32{"max_apps": maxApps, "max_concurrent_builds": maxBuilds}
			if err := c.do(cmd.Context(), http.MethodPut, "/api/v1/admin/workspaces/"+url.PathEscape(args[0])+"/quota", body, &q); err != nil {
				return err
			}
			return r.emit(q, func() { show(args[0], &q) })
		},
	}
	set.Flags().Int32Var(&maxApps, "max-apps", -1, "maximum number of apps")
	set.Flags().Int32Var(&maxBuilds, "max-builds", -1, "maximum concurrent builds")
	cmd.AddCommand(get, set)
	return cmd
}

func (r *runner) setDisabledCommand(disable bool) *cobra.Command {
	name, short := "enable", "Re-enable a disabled user"
	if disable {
		name, short = "disable", "Disable a user and revoke all their sessions and API tokens"
	}
	return &cobra.Command{
		Use: name + " <email>", Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			var page listPage[adminUser]
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/admin/users?email="+url.QueryEscape(args[0]), nil, &page); err != nil {
				return err
			}
			if len(page.Items) != 1 {
				return errors.New("no user with that email address")
			}
			var u adminUser
			if err := c.do(cmd.Context(), http.MethodPatch, "/api/v1/admin/users/"+url.PathEscape(page.Items[0].ID),
				map[string]bool{"disabled": disable}, &u); err != nil {
				return err
			}
			return r.emit(u, func() {
				if disable {
					r.printf("Disabled %s; their sessions and API tokens were revoked.\n", u.Email)
				} else {
					r.printf("Enabled %s. Old sessions and tokens stay revoked; they sign in again.\n", u.Email)
				}
			})
		},
	}
}

// fetchAllWithQuery is fetchAll for a path that already has a query string.
func fetchAllWithQuery[T any](cmd *cobra.Command, c *client, path string) ([]T, error) {
	if u, err := url.Parse(path); err == nil && u.RawQuery != "" {
		var page listPage[T]
		if err := c.do(cmd.Context(), http.MethodGet, path+"&limit=100", nil, &page); err != nil {
			return nil, err
		}
		return page.Items, nil
	}
	return fetchAll[T](cmd, c, path)
}
