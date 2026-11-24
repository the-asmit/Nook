package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type deviceStart struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type deviceToken struct {
	AccessToken string    `json:"access_token"`
	Token       tokenInfo `json:"token"`
}

type tokenInfo struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

type userInfo struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	Name            string `json:"name"`
	IsInstanceAdmin bool   `json:"is_instance_admin"`
}

type meInfo struct {
	User       userInfo `json:"user"`
	AuthMethod string   `json:"auth_method"`
}

// slowDownStep is the RFC 8628 interval increase after "slow_down".
const slowDownStep = 5 * time.Second

func (r *runner) loginCommand() *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login [server-url]",
		Short: "Sign in to a Nook server from this device",
		Long: "Starts a device login: the CLI shows a code, you approve it in your browser " +
			"(signing in there if needed), and the CLI receives an API token it saves locally.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := r.load()
			if err != nil {
				return err
			}
			server := s.server
			if len(args) == 1 {
				server = args[0]
			}
			if server == "" {
				return &usageError{errors.New("no server given: run 'nook login https://nook.example.com'")}
			}
			return r.login(cmd.Context(), s, server, !noBrowser)
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not try to open a browser")
	return cmd
}

func (r *runner) login(ctx context.Context, s *session, server string, openBrowser bool) error {
	c, err := newClient(server, "", userAgent())
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	clientName := "nook CLI"
	if hostname != "" {
		clientName += " on " + hostname
	}
	start, err := startDevice(ctx, c, clientName)
	if err != nil {
		return err
	}

	// Instructions go to stderr so `--output json` stdout stays parseable.
	_, _ = fmt.Fprintf(r.app.Stderr, "To sign in, open this page in a browser:\n\n    %s\n\nand check that it shows the code:  %s\n\n",
		start.VerificationURIComplete, start.UserCode)
	if openBrowser && r.app.OpenBrowser != nil {
		if r.app.OpenBrowser(start.VerificationURIComplete) == nil {
			_, _ = fmt.Fprintln(r.app.Stderr, "(Opened your browser.)")
		}
	}
	_, _ = fmt.Fprintln(r.app.Stderr, "Waiting for approval...")

	tok, err := pollForToken(ctx, c, start)
	if err != nil {
		return err
	}
	s.cfg.Server, s.cfg.Token = c.base, tok.AccessToken
	if s.cfg.Server != server {
		s.cfg.Workspace = ""
	}
	err = saveConfig(s.dir, s.cfg)
	if err != nil {
		return err
	}

	authed, err := newClient(c.base, tok.AccessToken, userAgent())
	if err != nil {
		return err
	}
	var me meInfo
	err = authed.do(ctx, http.MethodGet, "/api/v1/me", nil, &me)
	if err != nil {
		return fmt.Errorf("verify login: %w", err)
	}
	return r.emit(map[string]any{"server": c.base, "user": me.User, "token": tok.Token}, func() {
		r.printf("Logged in to %s as %s.\n", c.base, me.User.Email)
	})
}

func startDevice(ctx context.Context, c *client, clientName string) (*deviceStart, error) {
	var start deviceStart
	if err := c.do(ctx, http.MethodPost, "/api/v1/auth/device", map[string]string{"client_name": clientName}, &start); err != nil {
		return nil, fmt.Errorf("start login: %w", err)
	}
	return &start, nil
}

// pollForToken polls until the request is approved, denied or expires,
// honoring the server's interval and slow_down responses.
func pollForToken(ctx context.Context, c *client, start *deviceStart) (deviceToken, error) {
	interval := max(time.Duration(start.Interval)*time.Second, time.Second)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(start.ExpiresIn)*time.Second)
	defer cancel()
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return deviceToken{}, errors.New("login timed out before the code was approved; run 'nook login' again")
		case <-timer.C:
		}
		var tok deviceToken
		err := c.do(ctx, http.MethodPost, "/api/v1/auth/device/token", map[string]string{"device_code": start.DeviceCode}, &tok)
		switch {
		case err == nil:
			return tok, nil
		case isAPIError(err, "authorization_pending"):
			continue
		case isAPIError(err, "slow_down"):
			interval += slowDownStep
		case isAPIError(err, "access_denied"):
			return deviceToken{}, errors.New("login was denied in the browser")
		case isAPIError(err, "expired_token"):
			return deviceToken{}, errors.New("the login code expired; run 'nook login' again")
		default:
			return deviceToken{}, fmt.Errorf("complete login: %w", err)
		}
	}
}

func (r *runner) logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke this device's API token and forget it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			if err := c.do(cmd.Context(), http.MethodPost, "/api/v1/auth/logout", nil, nil); err != nil {
				return fmt.Errorf("revoke token: %w", err)
			}
			if !s.tokenFromEnv {
				s.cfg.Token = ""
				if err := saveConfig(s.dir, s.cfg); err != nil {
					return err
				}
			}
			return r.emit(map[string]any{"logged_out": true, "server": s.server}, func() {
				r.printf("Logged out of %s; the token was revoked.\n", s.server)
				if s.tokenFromEnv {
					r.printf("NOOK_TOKEN is still set in your environment; unset it.\n")
				}
			})
		},
	}
}

func (r *runner) whoamiCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the signed-in user",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, c, err := r.authed()
			if err != nil {
				return err
			}
			var me meInfo
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/me", nil, &me); err != nil {
				return err
			}
			return r.emit(map[string]any{"server": s.server, "user": me.User, "workspace": s.cfg.Workspace}, func() {
				admin := ""
				if me.User.IsInstanceAdmin {
					admin = " (instance admin)"
				}
				r.printf("%s <%s>%s\nserver:    %s\nworkspace: %s\n", dash(me.User.Name), me.User.Email, admin, s.server, dash(s.cfg.Workspace))
			})
		},
	}
}
