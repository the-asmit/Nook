package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/platform/health"
)

// Check outcomes reported by /readyz. Error details stay in the logs:
// they can contain internal host names that do not belong in a response.
const (
	checkOK          = "ok"
	checkUnavailable = "unavailable"
)

// LivenessResponse is the /healthz body.
type LivenessResponse struct {
	Status string `json:"status"`
}

// ReadinessResponse is the /readyz body.
type ReadinessResponse struct {
	// Status is "ready" or "not_ready".
	Status string `json:"status"`
	// Checks maps each dependency to "ok" or "unavailable".
	Checks map[string]string `json:"checks"`
	// Failing lists the unavailable dependencies, if any.
	Failing []string `json:"failing,omitempty"`
}

type healthHandlers struct {
	logger  *slog.Logger
	checks  []health.Check
	timeout time.Duration
}

// liveness answers whether the process is up and serving HTTP. It checks
// no dependencies on purpose: a database outage must not make the
// orchestrator restart every healthy server instance.
func (h *healthHandlers) liveness(c *gin.Context) {
	c.JSON(http.StatusOK, LivenessResponse{Status: "ok"})
}

// readiness answers whether this instance can serve traffic right now,
// i.e. whether its dependencies are reachable. Load balancers stop routing
// to an instance that returns 503 until it recovers.
func (h *healthHandlers) readiness(c *gin.Context) {
	ctx := c.Request.Context()
	report := health.Run(ctx, h.timeout, h.checks...)

	resp := ReadinessResponse{Status: "ready", Checks: make(map[string]string, len(report.Results))}
	for _, res := range report.Results {
		if res.Err == nil {
			resp.Checks[res.Name] = checkOK
			continue
		}
		resp.Checks[res.Name] = checkUnavailable
		h.logger.WarnContext(ctx, "readiness check failed", "dependency", res.Name, "error", res.Err.Error())
	}
	if !report.Healthy() {
		resp.Status = "not_ready"
		resp.Failing = report.Failing()
		c.JSON(http.StatusServiceUnavailable, resp)
		return
	}
	c.JSON(http.StatusOK, resp)
}
