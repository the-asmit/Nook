package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"uuid"

	"github.com/gin-gonic/gin"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/nodes"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Errors of the admin endpoints.
var (
	errForbiddenAdmin     = &apperr.Error{Kind: apperr.KindForbidden, Code: "instance_admin_required", Message: "only instance administrators may do this"}
	errInvalidEmailFilter = apperr.Invalid("invalid_email", "email filter is too long")
	errMissingDisabled    = apperr.Invalid("invalid_body", `"disabled" (true or false) is required`)
	errInvalidMaxUses     = apperr.Invalid("invalid_max_uses", "max_uses must be between 1 and 1000")
	errInvalidExpiry      = apperr.Invalid("invalid_expiry", "expires_in_seconds must be between 60 and 604800")
)

// HeartbeatView is a node's latest heartbeat.
type HeartbeatView struct {
	ReceivedAt           time.Time `json:"received_at"`
	MemoryAvailableBytes int64     `json:"memory_available_bytes"`
	CPULoad1m            float64   `json:"cpu_load_1m"`
	DiskFreeBytes        int64     `json:"disk_free_bytes"`
	RunningContainers    int32     `json:"running_containers"`
	DockerReachable      bool      `json:"docker_reachable"`
	AgentVersion         string    `json:"agent_version"`
	UptimeSeconds        int64     `json:"uptime_seconds"`
	// BuildsUnavailableReason says why the node cannot build right now.
	BuildsUnavailableReason string `json:"builds_unavailable_reason"`
}

// NodeView is a worker node.
type NodeView struct {
	ID               uuid.UUID         `json:"id"`
	Name             string            `json:"name"`
	Status           string            `json:"status"`
	Draining         bool              `json:"draining"`
	Labels           map[string]string `json:"labels"`
	Hostname         string            `json:"hostname"`
	Addresses        []string          `json:"addresses"`
	CPUCount         int32             `json:"cpu_count"`
	MemoryTotalBytes int64             `json:"memory_total_bytes"`
	DiskTotalBytes   int64             `json:"disk_total_bytes"`
	DockerVersion    string            `json:"docker_version"`
	AgentVersion     string            `json:"agent_version"`
	OS               string            `json:"os"`
	Arch             string            `json:"arch"`
	// AdvertiseAddress is the private address the node publishes apps on.
	AdvertiseAddress string `json:"advertise_address"`
	BuildSlots       int32  `json:"build_slots"`
	// BuildsUnavailableReason says why the node cannot build (with the
	// fix), or is empty.
	BuildsUnavailableReason string `json:"builds_unavailable_reason"`
	// Where app containers would reach an app database server on the node,
	// or why the node cannot host one.
	DatabaseAddress           string         `json:"database_address"`
	DatabasePort              int32          `json:"database_port"`
	DatabaseUnavailableReason string         `json:"database_unavailable_reason"`
	JoinedAt                  time.Time      `json:"joined_at"`
	LastHeartbeatAt           *time.Time     `json:"last_heartbeat_at"`
	Heartbeat                 *HeartbeatView `json:"heartbeat"`
}

// NodeEventView is one state transition.
type NodeEventView struct {
	From   *string   `json:"from"`
	To     string    `json:"to"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// NodeDetailView is a node with its recent history.
type NodeDetailView struct {
	NodeView
	// ActiveInstances counts app instances still running (or stopping) on
	// the node: zero once a drain is complete.
	ActiveInstances int64           `json:"active_instances"`
	Events          []NodeEventView `json:"events"`
}

func nodeView(n *store.Node, hb *nodes.Sample) NodeView {
	labels := map[string]string{}
	_ = json.Unmarshal(n.Labels, &labels) // Stored by us; always a JSON object.
	v := NodeView{
		ID: n.ID, Name: n.Name, Status: string(n.Status), Draining: n.Draining, Labels: labels,
		Hostname: n.Hostname, Addresses: n.Addresses, CPUCount: n.CpuCount, MemoryTotalBytes: n.MemoryTotalBytes,
		DiskTotalBytes: n.DiskTotalBytes, DockerVersion: n.DockerVersion, AgentVersion: n.AgentVersion,
		OS: n.Os, Arch: n.Arch, JoinedAt: n.JoinedAt, LastHeartbeatAt: n.LastHeartbeatAt,
		AdvertiseAddress: n.AdvertiseAddress, BuildSlots: n.BuildSlots, BuildsUnavailableReason: n.BuildsUnavailableReason,
		DatabaseAddress: n.DbAddress, DatabasePort: n.DbPort, DatabaseUnavailableReason: n.DbUnavailableReason,
	}
	if hb != nil {
		v.Heartbeat = &HeartbeatView{
			ReceivedAt: hb.ReceivedAt, MemoryAvailableBytes: hb.MemoryAvailableBytes, CPULoad1m: hb.CPULoad1m,
			DiskFreeBytes: hb.DiskFreeBytes, RunningContainers: hb.RunningContainers, DockerReachable: hb.DockerReachable,
			AgentVersion: hb.AgentVersion, UptimeSeconds: int64(hb.Uptime.Seconds()),
			BuildsUnavailableReason: hb.BuildsUnavailableReason,
		}
		// Redis holds the freshest heartbeat time; Postgres lags by design.
		if v.LastHeartbeatAt == nil || hb.ReceivedAt.After(*v.LastHeartbeatAt) {
			v.LastHeartbeatAt = &hb.ReceivedAt
		}
	}
	return v
}

type nameCursor struct {
	Name string `json:"n"`
}

func (h *V1) listNodes(c *gin.Context) {
	var cur nameCursor
	limit, err := pageParams(c, &cur)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	ns, err := h.Nodes.List(c.Request.Context(), cur.Name, limit+1)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	views := make([]NodeView, 0, len(ns))
	for i := range ns {
		hb, err := h.Nodes.LatestHeartbeat(c.Request.Context(), ns[i].ID)
		if err != nil {
			writeError(c, h.Logger, err)
			return
		}
		views = append(views, nodeView(&ns[i], hb))
	}
	c.JSON(http.StatusOK, page(views, limit, func(v *NodeView) NodeView { return *v }, func(v *NodeView) any { return nameCursor{Name: v.Name} }))
}

func (h *V1) getNode(c *gin.Context) {
	ctx := c.Request.Context()
	n, err := h.Nodes.Resolve(ctx, c.Param("node"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	hb, err := h.Nodes.LatestHeartbeat(ctx, n.ID)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	evs, err := h.Nodes.Events(ctx, n.ID, 20)
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	active, err := h.Store.CountActiveInstancesOnNode(ctx, &n.ID)
	if err != nil {
		writeError(c, h.Logger, fmt.Errorf("count instances: %w", err))
		return
	}
	out := NodeDetailView{NodeView: nodeView(&n, hb), ActiveInstances: active, Events: make([]NodeEventView, 0, len(evs))}
	for _, e := range evs {
		ev := NodeEventView{To: string(e.ToStatus), Reason: e.Reason, At: e.CreatedAt}
		if e.FromStatus != nil {
			from := string(*e.FromStatus)
			ev.From = &from
		}
		out.Events = append(out.Events, ev)
	}
	c.JSON(http.StatusOK, out)
}

func (h *V1) setDraining(draining bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		n, err := h.Nodes.SetDraining(c.Request.Context(), actor(c), c.Param("node"), draining)
		if err != nil {
			writeError(c, h.Logger, err)
			return
		}
		c.JSON(http.StatusOK, nodeView(&n, nil))
	}
}

func (h *V1) removeNode(c *gin.Context) {
	if _, err := h.Nodes.Remove(c.Request.Context(), actor(c), c.Param("node")); err != nil {
		writeError(c, h.Logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// InspectView is live information gathered from a node's agent.
type InspectView struct {
	Node       string                 `json:"node"`
	Docker     DockerInfoView         `json:"docker"`
	Containers []ManagedContainerView `json:"containers"`
}

// DockerInfoView is the node's Docker engine.
type DockerInfoView struct {
	ServerVersion     string `json:"server_version"`
	APIVersion        string `json:"api_version"`
	OperatingSystem   string `json:"operating_system"`
	KernelVersion     string `json:"kernel_version"`
	Architecture      string `json:"architecture"`
	CPUs              int32  `json:"cpus"`
	MemoryTotalBytes  int64  `json:"memory_total_bytes"`
	StorageDriver     string `json:"storage_driver"`
	ContainersRunning int32  `json:"containers_running"`
	ContainersTotal   int32  `json:"containers_total"`
	Images            int32  `json:"images"`
}

// ManagedContainerView is a container Nook manages on the node.
type ManagedContainerView struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	State     string            `json:"state"`
	Status    string            `json:"status"`
	Labels    map[string]string `json:"labels"`
	CreatedAt time.Time         `json:"created_at"`
}

func (h *V1) inspectNode(c *gin.Context) {
	ctx := c.Request.Context()
	n, err := h.Nodes.Resolve(ctx, c.Param("node"))
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	res, err := h.Hub.Dispatch(ctx, n.ID, &agentv1.Command{Kind: &agentv1.Command_InspectNode{InspectNode: &agentv1.InspectNodeCommand{}}}, h.Nodes.CommandTimeout())
	if err != nil {
		writeError(c, h.Logger, err)
		return
	}
	if e := res.GetError(); e != nil {
		code := "agent_error"
		if e.GetCode() == agentv1.CommandErrorCode_COMMAND_ERROR_CODE_DOCKER_UNAVAILABLE {
			code = "docker_unavailable"
		}
		writeError(c, h.Logger, apperr.Unavailable(code, "%s", e.GetMessage()))
		return
	}
	in := res.GetInspectNode()
	d := in.GetDocker()
	out := InspectView{Node: n.Name, Containers: []ManagedContainerView{}, Docker: DockerInfoView{
		ServerVersion: d.GetServerVersion(), APIVersion: d.GetApiVersion(), OperatingSystem: d.GetOperatingSystem(),
		KernelVersion: d.GetKernelVersion(), Architecture: d.GetArchitecture(), CPUs: d.GetCpus(),
		MemoryTotalBytes: d.GetMemoryTotalBytes(), StorageDriver: d.GetStorageDriver(),
		ContainersRunning: d.GetContainersRunning(), ContainersTotal: d.GetContainersTotal(), Images: d.GetImages(),
	}}
	for _, ct := range in.GetContainers() {
		labels := ct.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		out.Containers = append(out.Containers, ManagedContainerView{
			ID: ct.GetId(), Name: ct.GetName(), Image: ct.GetImage(), State: ct.GetState(), Status: ct.GetStatus(),
			Labels: labels, CreatedAt: ct.GetCreatedAt().AsTime(),
		})
	}
	c.JSON(http.StatusOK, out)
}
