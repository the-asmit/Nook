package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/ratelimit"
	"github.com/the-asmit/nook/internal/rollout"
)

// RouteAppLogs streams app logs; it is exempt from the request timeout.
const RouteAppLogs = "/api/v1/workspaces/:slug/apps/:app/logs"

// appLogsRule limits log requests per user: each one makes a node read
// and ship container output.
var appLogsRule = ratelimit.Rule{Name: "app_logs", Limit: 30, Window: time.Minute}

// EnvVarView is an environment variable; a secret's value is never shown.
type EnvVarView struct {
	Key string `json:"key"`
	// Value is null for secrets.
	Value     *string   `json:"value"`
	Secret    bool      `json:"secret"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EnvListResponse lists an app's variables.
type EnvListResponse struct {
	Items []EnvVarView `json:"items"`
}

// SetEnvRequest sets variables.
type SetEnvRequest struct {
	Vars map[string]string `json:"vars"`
	// Secret marks every variable in the request as a secret (admins and
	// owners only).
	Secret bool `json:"secret"`
}

// EnvChangeResponse is the app's variables after a change and the
// deployment releasing them, if the app was live.
type EnvChangeResponse struct {
	Items      []EnvVarView    `json:"items"`
	Deployment *DeploymentView `json:"deployment"`
}

func envViews(vars []apps.EnvVar) []EnvVarView {
	out := make([]EnvVarView, 0, len(vars))
	for i := range vars {
		v := EnvVarView{Key: vars[i].Key, Secret: vars[i].Secret, UpdatedAt: vars[i].UpdatedAt}
		if !vars[i].Secret {
			v.Value = &vars[i].Value
		}
		out = append(out, v)
	}
	return out
}

func (h *V1) listEnv(c *gin.Context) {
	vars, err := h.Apps.ListEnv(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, EnvListResponse{Items: envViews(vars)})
}

func (h *V1) setEnv(c *gin.Context) {
	var req SetEnvRequest
	if !decodeJSON(c, &req) {
		return
	}
	change, err := h.Apps.SetEnv(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), req.Vars, req.Secret)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.respondEnvChange(c, change)
}

func (h *V1) unsetEnv(c *gin.Context) {
	change, err := h.Apps.UnsetEnv(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), c.Param("key"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.respondEnvChange(c, change)
}

func (h *V1) respondEnvChange(c *gin.Context, change apps.EnvChange) {
	vars, err := h.Apps.ListEnv(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	res := EnvChangeResponse{Items: envViews(vars)}
	if change.Deployment != nil {
		app, err := h.Apps.Get(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
		if err != nil {
			writeError(c, h.Logger, err)
			return
		}
		v := h.deploymentView(&app, change.Deployment, nil)
		res.Deployment = &v
	}
	c.JSON(http.StatusOK, res)
}

// RollbackRequest picks the deployment to release again (0 or omitted:
// the newest earlier deployment that was live).
type RollbackRequest struct {
	To int32 `json:"to"`
}

func (h *V1) rollback(c *gin.Context) {
	var req RollbackRequest
	if !decodeJSON(c, &req) {
		return
	}
	if req.To < 0 {
		writeError(c, h.Logger, apperr.Invalid("invalid_body", `"to" must be a deployment number`))
		return
	}
	d, err := h.Apps.Rollback(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), req.To)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	app, err := h.Apps.Get(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusCreated, h.deploymentView(&app, &d, nil))
}

// parseLogOptions reads follow, tail and since (a duration such as 10m,
// or an RFC 3339 time).
func parseLogOptions(c *gin.Context, now time.Time) (rollout.LogOptions, error) {
	opts := rollout.LogOptions{Follow: c.Query("follow") == "1" || c.Query("follow") == "true"}
	if t := c.Query("tail"); t != "" {
		n, err := strconv.ParseInt(t, 10, 32)
		if err != nil || n < 0 || n > 10000 {
			return opts, apperr.Invalid("invalid_tail", "tail must be a number of lines from 0 to 10000")
		}
		opts.Tail = int32(n)
	}
	if s := c.Query("since"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			opts.Since = now.Add(-d)
		} else if t, err := time.Parse(time.RFC3339, s); err == nil {
			opts.Since = t
		} else {
			return opts, apperr.Invalid("invalid_since", "since must be a duration such as 10m or an RFC 3339 time")
		}
	}
	return opts, nil
}

// appLogs streams an app's runtime output as Server-Sent Events: "line"
// events ({time, stream, text}) and a final "end" event.
func (h *V1) appLogs(c *gin.Context) {
	opts, err := parseLogOptions(c, time.Now())
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	res, err := h.Limiter.Allow(c.Request.Context(), appLogsRule, principal(c).User.ID.String())
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if !res.Allowed {
		c.Header("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())+1))
		writeError(c, h.Logger, apperr.RateLimited("too many log requests; retry later"))
		return
	}
	inst, err := h.Apps.LogInstance(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	write, stop := startSSE(c)
	defer stop()
	err = h.AppLogs.Stream(c.Request.Context(), &inst, opts, func(l rollout.LogLine) error {
		return write("line", l)
	})
	end := map[string]string{"reason": "end of output"}
	if err != nil {
		var ae *apperr.Error
		if errors.As(err, &ae) {
			end["reason"] = ae.Message
		} else {
			h.Logger.WarnContext(c.Request.Context(), "app log stream failed", "error", err.Error())
			end["reason"] = "the log stream failed"
		}
	}
	end["reason"] = strings.TrimSpace(end["reason"])
	_ = write("end", end)
}
