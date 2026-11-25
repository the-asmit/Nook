package api

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/apps"
	"github.com/the-asmit/nook/internal/builds"
	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/store"
)

// BuildView is one build attempt.
type BuildView struct {
	Attempt      int32      `json:"attempt"`
	Node         string     `json:"node"`
	DispatchedAt time.Time  `json:"dispatched_at"`
	StartedAt    *time.Time `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	Result       *string    `json:"result"`
	Message      string     `json:"message"`
}

// DeploymentView is a deployment.
type DeploymentView struct {
	Number       int32   `json:"number"`
	Status       string  `json:"status"`
	SourceSize   int64   `json:"source_size"`
	SourceSHA256 string  `json:"source_sha256"`
	ImageDigest  *string `json:"image_digest"`
	// Image is the full reference by digest (registry/repository@digest).
	Image           *string     `json:"image"`
	FailureReason   string      `json:"failure_reason"`
	CancelRequested bool        `json:"cancel_requested"`
	CreatedAt       time.Time   `json:"created_at"`
	QueuedAt        *time.Time  `json:"queued_at"`
	BuildingAt      *time.Time  `json:"building_at"`
	BuiltAt         *time.Time  `json:"built_at"`
	FailedAt        *time.Time  `json:"failed_at"`
	CancelledAt     *time.Time  `json:"canceled_at"`
	ImageDeleted    bool        `json:"image_deleted"`
	Builds          []BuildView `json:"builds,omitempty"`
	// Kind is "build", "config" (new environment) or "rollback".
	Kind string `json:"kind"`
	// RollbackTo is the deployment a rollback releases again.
	RollbackTo   *int32     `json:"rollback_to"`
	DeployingAt  *time.Time `json:"deploying_at"`
	LiveAt       *time.Time `json:"live_at"`
	SupersededAt *time.Time `json:"superseded_at"`
	RolledBackAt *time.Time `json:"rolled_back_at"`
	// Instance is the deployment's newest instance (detail views only).
	Instance *InstanceView `json:"instance,omitempty"`
}

// InstanceView is where and how an app instance runs.
type InstanceView struct {
	Node  string `json:"node"`
	State string `json:"state"`
	// Address and HostPort are where the node publishes the app.
	Address       string     `json:"address"`
	HostPort      *int32     `json:"host_port"`
	RestartCount  int32      `json:"restart_count"`
	LastError     string     `json:"last_error"`
	StartedAt     *time.Time `json:"started_at"`
	LastHealthyAt *time.Time `json:"last_healthy_at"`
	// StartupLog is the output of an instance that failed to start.
	StartupLog string    `json:"startup_log,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func instanceView(i *store.AppInstance) *InstanceView {
	if i == nil {
		return nil
	}
	return &InstanceView{
		Node: i.NodeName, State: string(i.State), Address: i.Address, HostPort: i.HostPort, RestartCount: i.RestartCount,
		LastError: i.LastError, StartedAt: i.StartedAt, LastHealthyAt: i.LastHealthyAt, StartupLog: i.StartupLog, CreatedAt: i.CreatedAt,
	}
}

func (h *V1) detailView(d *apps.Detail) DeploymentView {
	v := h.deploymentView(&d.App, &d.Deployment, d.Builds)
	v.Instance = instanceView(d.Instance)
	return v
}

func (h *V1) deploymentView(app *store.App, d *store.Deployment, bs []store.Build) DeploymentView {
	v := DeploymentView{
		Number: d.Number, Status: string(d.Status), SourceSize: d.SourceSize, SourceSHA256: hex.EncodeToString(d.SourceSha256),
		ImageDigest: d.ImageDigest, FailureReason: d.FailureReason, CancelRequested: d.CancelRequestedAt != nil,
		CreatedAt: d.CreatedAt, QueuedAt: d.QueuedAt, BuildingAt: d.BuildingAt, BuiltAt: d.BuiltAt,
		FailedAt: d.FailedAt, CancelledAt: d.CancelledAt, ImageDeleted: d.ImageDeletedAt != nil,
		Kind: string(d.Kind), RollbackTo: d.RollbackTo, DeployingAt: d.DeployingAt, LiveAt: d.LiveAt,
		SupersededAt: d.SupersededAt, RolledBackAt: d.RolledBackAt,
	}
	if d.ImageDigest != nil {
		ref := h.RegistryAddr + "/" + apps.RepositoryName(app.WorkspaceID, app.ID) + "@" + *d.ImageDigest
		v.Image = &ref
	}
	for i := range bs {
		b := &bs[i]
		bv := BuildView{Attempt: b.Attempt, Node: b.NodeName, DispatchedAt: b.DispatchedAt, StartedAt: b.StartedAt,
			FinishedAt: b.FinishedAt, Message: b.Message}
		if b.Result != nil {
			r := string(*b.Result)
			bv.Result = &r
		}
		v.Builds = append(v.Builds, bv)
	}
	return v
}

// CreateDeploymentRequest announces the source archive to upload.
type CreateDeploymentRequest struct {
	SourceSize int64 `json:"source_size"`
	// SourceSHA256 is the archive's SHA-256, hex-encoded.
	SourceSHA256 string `json:"source_sha256"`
}

// CreateDeploymentResponse says where to upload the archive. The upload
// URL is a credential: it is shown to the caller only, never logged.
type CreateDeploymentResponse struct {
	Deployment DeploymentView  `json:"deployment"`
	Upload     objstore.Upload `json:"upload"`
	// MaxSourceBytes is the server's archive size limit.
	MaxSourceBytes int64 `json:"max_source_bytes"`
}

func (h *V1) createDeployment(c *gin.Context) {
	var req CreateDeploymentRequest
	if !decodeJSON(c, &req) {
		return
	}
	sum, err := hex.DecodeString(req.SourceSHA256)
	if err != nil || len(sum) != 32 {
		writeError(c, h.Logger, apperr.Invalid("invalid_checksum", "source_sha256 must be 64 hex digits"))
		return
	}
	up, err := h.Apps.CreateDeployment(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), req.SourceSize, sum)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusCreated, CreateDeploymentResponse{
		Deployment: h.deploymentView(&up.App, &up.Deployment, nil), Upload: up.Upload, MaxSourceBytes: h.MaxSourceBytes,
	})
}

func number(c *gin.Context) (int32, error) {
	n, err := strconv.ParseInt(c.Param("number"), 10, 32)
	if err != nil || n < 1 {
		return 0, apperr.NotFound("deployment not found")
	}
	return int32(n), nil
}

func (h *V1) confirmUpload(c *gin.Context) {
	n, err := number(c)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	d, err := h.Apps.ConfirmUpload(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), n)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.respondDeployment(c, d.Number)
}

func (h *V1) respondDeployment(c *gin.Context, n int32) {
	detail, err := h.Apps.GetDeployment(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), n)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, h.detailView(&detail))
}

func (h *V1) getDeployment(c *gin.Context) {
	n, err := number(c)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.respondDeployment(c, n)
}

type numberCursor struct {
	Number int32 `json:"n"`
}

func (h *V1) listDeployments(c *gin.Context) {
	var cur numberCursor
	limit, err := pageParams(c, &cur)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	app, err := h.Apps.Get(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	list, err := h.Apps.ListDeployments(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), cur.Number, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.JSON(http.StatusOK, page(list, limit, func(d *store.Deployment) DeploymentView { return h.deploymentView(&app, d, nil) },
		func(d *store.Deployment) any { return numberCursor{Number: d.Number} }))
}

func (h *V1) cancelDeployment(c *gin.Context) {
	n, err := number(c)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if _, err := h.Apps.Cancel(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), n); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	h.respondDeployment(c, n)
}

// maxFollow bounds one SSE connection; clients reconnect if needed.
const maxFollow = 3 * time.Hour

// errFollowLimit ends a follow that reached maxFollow.
var errFollowLimit = errors.New("follow limit reached")

func (h *V1) buildLog(c *gin.Context) {
	n, err := number(c)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	detail, err := h.Apps.GetDeployment(c.Request.Context(), actor(c), c.Param("slug"), c.Param("app"), n)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if c.Query("follow") != "1" {
		text, err := h.Logs.Read(c.Request.Context(), detail.Deployment.ID, detail.Builds)
		if err != nil {
			writeError(c, h.Logger, err)
			return
		}
		c.Header("Cache-Control", "no-store")
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(text))
		return
	}
	h.followLog(c, &detail)
}

// followLog streams the log as Server-Sent Events: "line" events with the
// output, "status" events when the deployment's status changes and a
// final "end" event. The route is exempt from the request timeout.
func (h *V1) followLog(c *gin.Context, detail *apps.Detail) {
	ctx := c.Request.Context()
	write, stop := startSSE(c)
	defer stop()
	deadline := time.Now().Add(maxFollow)
	who := actor(c)
	_ = h.Logs.Follow(ctx, detail.Deployment.ID, func(e builds.Event) error {
		if time.Now().After(deadline) {
			return errFollowLimit
		}
		switch e.Type {
		case "line":
			return write("line", map[string]string{"text": e.Text})
		case "status":
			return write("status", map[string]string{"status": string(e.Status)})
		default:
			d, err := h.Apps.GetDeployment(ctx, who, c.Param("slug"), c.Param("app"), detail.Deployment.Number)
			if err != nil {
				return write("end", map[string]string{"status": string(e.Status)})
			}
			return write("end", h.detailView(&d))
		}
	})
}
