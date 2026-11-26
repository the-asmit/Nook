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

type accessInfo struct {
	Mode          string `json:"mode"`
	Effective     string `json:"effective"`
	PublicAllowed bool   `json:"public_allowed"`
	Grants        []struct {
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"created_at"`
	} `json:"grants"`
}

func (r *runner) printAccess(app string, a *accessInfo) {
	r.printf("App:     %s\nAccess:  %s", app, a.Mode)
	if a.Effective != a.Mode {
		r.printf(" (in effect: %s; this installation does not allow public apps)", a.Effective)
	}
	r.printf("\n")
	switch a.Effective {
	case "workspace":
		r.printf("Who:     workspace members, plus the emails below\n")
	case "restricted":
		r.printf("Who:     workspace admins and owners, plus the emails below\n")
	default:
		r.printf("Who:     anyone, without signing in\n")
	}
	if len(a.Grants) == 0 {
		r.printf("Grants:  none\n")
		return
	}
	r.table("GRANTED EMAIL\tSINCE", func(w *tabwriter.Writer) {
		for _, g := range a.Grants {
			_, _ = fmt.Fprintf(w, "%s\t%s\n", g.Email, g.CreatedAt.Local().Format("2006-01-02 15:04"))
		}
	})
}

func (r *runner) accessCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "access", Short: "Show and manage who may open an app (admins and owners manage, members view)"}
	call := func(cmd *cobra.Command, method, app, suffix string, body any) (*accessInfo, error) {
		ws, c, err := r.appContext()
		if err != nil {
			return nil, err
		}
		var a accessInfo
		if err := c.do(cmd.Context(), method, appPath(ws, app)+"/access"+suffix, body, &a); err != nil {
			return nil, err
		}
		return &a, nil
	}
	show := &cobra.Command{
		Use: "show <app>", Short: "Show the app's access mode and grants", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := call(cmd, http.MethodGet, args[0], "", nil)
			if err != nil {
				return err
			}
			return r.emit(a, func() { r.printAccess(args[0], a) })
		},
	}
	var mode string
	set := &cobra.Command{
		Use: "set <app> --mode workspace|restricted|public", Short: "Set the access mode", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if mode != "workspace" && mode != "restricted" && mode != "public" {
				return &usageError{errors.New("--mode must be workspace, restricted or public")}
			}
			a, err := call(cmd, http.MethodPut, args[0], "", map[string]string{"mode": mode})
			if err != nil {
				return err
			}
			return r.emit(a, func() { r.printAccess(args[0], a) })
		},
	}
	set.Flags().StringVar(&mode, "mode", "", "workspace (members), restricted (admins, owners and grants) or public (anyone)")
	grant := &cobra.Command{
		Use: "grant <app> <email>...", Short: "Give people access by email (members or not)", Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := call(cmd, http.MethodPost, args[0], "/grants", map[string][]string{"emails": args[1:]})
			if err != nil {
				return err
			}
			return r.emit(a, func() { r.printAccess(args[0], a) })
		},
	}
	revoke := &cobra.Command{
		Use: "revoke <app> <email>", Short: "Remove a grant (takes effect within the gateway's access cache, 30 s by default)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := call(cmd, http.MethodDelete, args[0], "/grants/"+url.PathEscape(args[1]), nil)
			if err != nil {
				return err
			}
			return r.emit(a, func() { r.printAccess(args[0], a) })
		},
	}
	cmd.AddCommand(show, set, grant, revoke)
	return cmd
}

func (r *runner) openCommand() *cobra.Command {
	return &cobra.Command{
		Use: "open <app>", Short: "Open the app's URL in the browser", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, c, err := r.appContext()
			if err != nil {
				return err
			}
			var a appInfo
			if err := c.do(cmd.Context(), http.MethodGet, appPath(ws, args[0]), nil, &a); err != nil {
				return err
			}
			r.printf("%s\n", a.URL)
			if r.app.OpenBrowser != nil {
				if err := r.app.OpenBrowser(a.URL); err != nil {
					r.status("Could not open a browser; open the URL above.")
				}
			}
			return nil
		},
	}
}
