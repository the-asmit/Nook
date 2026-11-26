package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type heartbeatInfo struct {
	ReceivedAt           time.Time `json:"received_at"`
	MemoryAvailableBytes int64     `json:"memory_available_bytes"`
	CPULoad1m            float64   `json:"cpu_load_1m"`
	DiskFreeBytes        int64     `json:"disk_free_bytes"`
	RunningContainers    int32     `json:"running_containers"`
	DockerReachable      bool      `json:"docker_reachable"`
	UptimeSeconds        int64     `json:"uptime_seconds"`
}

type nodeInfo struct {
	ID               string            `json:"id"`
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
	AdvertiseAddress string            `json:"advertise_address"`
	BuildSlots       int32             `json:"build_slots"`
	// BuildsUnavailableReason says why the node cannot build, with the fix.
	BuildsUnavailableReason string         `json:"builds_unavailable_reason"`
	JoinedAt                time.Time      `json:"joined_at"`
	LastHeartbeatAt         *time.Time     `json:"last_heartbeat_at"`
	Heartbeat               *heartbeatInfo `json:"heartbeat"`
}

type inspectInfo struct {
	Node   string `json:"node"`
	Docker struct {
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
	} `json:"docker"`
	Containers []struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Image  string `json:"image"`
		State  string `json:"state"`
		Status string `json:"status"`
	} `json:"containers"`
}

// bytesHuman formats a byte count with binary units.
func bytesHuman(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func ago(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return time.Since(*t).Truncate(time.Second).String() + " ago"
}

func (r *runner) nodeCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "node", Short: "Manage worker nodes (instance admins)"}
	ref := func(args []string) string { return url.PathEscape(args[0]) }

	list := &cobra.Command{
		Use: "list", Short: "List worker nodes", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			items, err := fetchAll[nodeInfo](cmd, c, "/api/v1/nodes")
			if err != nil {
				return err
			}
			return r.emit(items, func() {
				r.table("NAME\tSTATUS\tCPUS\tMEMORY (FREE/TOTAL)\tDISK (FREE/TOTAL)\tCONTAINERS\tDOCKER\tLAST HEARTBEAT", func(w *tabwriter.Writer) {
					for i := range items {
						n := &items[i]
						mem, dsk, ctr, dock := "-", "-", "-", dash(n.DockerVersion)
						if hb := n.Heartbeat; hb != nil {
							mem = bytesHuman(hb.MemoryAvailableBytes) + " / " + bytesHuman(n.MemoryTotalBytes)
							dsk = bytesHuman(hb.DiskFreeBytes) + " / " + bytesHuman(n.DiskTotalBytes)
							ctr = strconv.Itoa(int(hb.RunningContainers))
							if !hb.DockerReachable {
								dock = "unreachable"
							}
						}
						_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", n.Name, n.Status, n.CPUCount, mem, dsk, ctr, dock, ago(n.LastHeartbeatAt))
					}
				})
			})
		},
	}

	inspect := &cobra.Command{
		Use: "inspect <name|id>", Short: "Show live Docker information from a node's agent", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			var node nodeInfo
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/nodes/"+ref(args), nil, &node); err != nil {
				return err
			}
			var live inspectInfo
			if err := c.do(cmd.Context(), http.MethodPost, "/api/v1/nodes/"+ref(args)+"/inspect", nil, &live); err != nil {
				return err
			}
			return r.emit(map[string]any{"node": node, "live": live}, func() { r.printInspect(&node, &live) })
		},
	}

	drain := r.drainCommand()
	undrain := r.nodeAction("undrain", "Make a drained node available again", http.MethodPost, "/undrain")
	remove := r.nodeAction("remove", "Remove a node: revoke its certificates and disconnect its agent", http.MethodDelete, "")

	cmd.AddCommand(list, inspect, drain, undrain, remove, r.joinTokenCommand())
	return cmd
}

// drainCommand is `nook node drain`: nothing new is placed on the node and
// every app moves off it with zero downtime (a replacement starts on
// another node and serves before the old instance stops); it waits until
// the node runs no app.
func (r *runner) drainCommand() *cobra.Command {
	var noWait bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use: "drain <name|id>", Short: "Move every app off a node (zero downtime) and place nothing new on it", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			path := "/api/v1/nodes/" + url.PathEscape(args[0])
			if err := c.do(cmd.Context(), http.MethodPost, path+"/drain", nil, nil); err != nil {
				return err
			}
			if noWait {
				return r.emit(map[string]string{"node": args[0], "result": "draining"}, func() {
					r.printf("Node %s is draining; its apps move to other nodes.\n", args[0])
				})
			}
			start, deadline, last := time.Now(), time.Now().Add(timeout), int64(-1)
			for {
				var n struct {
					ActiveInstances int64 `json:"active_instances"`
				}
				if err := c.do(cmd.Context(), http.MethodGet, path, nil, &n); err != nil {
					return err
				}
				if n.ActiveInstances == 0 {
					took := time.Since(start).Round(100 * time.Millisecond)
					return r.emit(map[string]any{"node": args[0], "result": "drained", "seconds": took.Seconds()}, func() {
						r.printf("Node %s is drained: no app runs on it (took %s).\n", args[0], took)
					})
				}
				if n.ActiveInstances != last {
					r.status("Draining %s: %d app instance(s) still on it...", args[0], n.ActiveInstances)
					last = n.ActiveInstances
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("node %s still runs %d app instance(s) after %s; other nodes may lack capacity (the apps keep running on it)",
						args[0], n.ActiveInstances, timeout)
				}
				select {
				case <-cmd.Context().Done():
					return cmd.Context().Err()
				case <-time.After(time.Second):
				}
			}
		},
	}
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "return once the node is draining instead of waiting for its apps to move")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "how long to wait for the apps to move")
	return cmd
}

func (r *runner) nodeAction(name, short, method, suffix string) *cobra.Command {
	return &cobra.Command{
		Use: name + " <name|id>", Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			if err := c.do(cmd.Context(), method, "/api/v1/nodes/"+url.PathEscape(args[0])+suffix, nil, nil); err != nil {
				return err
			}
			past := map[string]string{"drain": "drained", "undrain": "undrained", "remove": "removed"}[name]
			return r.emit(map[string]string{"node": args[0], "result": past}, func() { r.printf("Node %s %s.\n", args[0], past) })
		},
	}
}

func (r *runner) printInspect(n *nodeInfo, live *inspectInfo) {
	r.printf("Node:      %s (%s)\nStatus:    %s%s\nHost:      %s %s/%s  %s\n", n.Name, n.ID, n.Status,
		map[bool]string{true: " (draining)", false: ""}[n.Draining], n.Hostname, n.OS, n.Arch, strings.Join(n.Addresses, ", "))
	r.printf("Resources: %d CPUs, %s memory, %s disk\nAgent:     %s, last heartbeat %s\n", n.CPUCount,
		bytesHuman(n.MemoryTotalBytes), bytesHuman(n.DiskTotalBytes), dash(n.AgentVersion), ago(n.LastHeartbeatAt))
	r.printf("Apps on:   %s\n", dash(n.AdvertiseAddress))
	switch {
	case n.BuildSlots == 0:
		r.printf("Builds:    off (0 build slots)\n")
	case n.BuildsUnavailableReason != "":
		r.printf("Builds:    UNAVAILABLE: %s\n", n.BuildsUnavailableReason)
	default:
		r.printf("Builds:    %d slots\n", n.BuildSlots)
	}
	if len(n.Labels) > 0 {
		keys := make([]string, 0, len(n.Labels))
		for k := range n.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]string, len(keys))
		for i, k := range keys {
			pairs[i] = k + "=" + n.Labels[k]
		}
		r.printf("Labels:    %s\n", strings.Join(pairs, ", "))
	}
	d := live.Docker
	r.printf("\nDocker %s (API %s) on %s, kernel %s, %s\n", d.ServerVersion, d.APIVersion, d.OperatingSystem, d.KernelVersion, d.Architecture)
	r.printf("  %d CPUs, %s memory, storage driver %s\n  containers: %d running / %d total, %d images\n",
		d.CPUs, bytesHuman(d.MemoryTotalBytes), d.StorageDriver, d.ContainersRunning, d.ContainersTotal, d.Images)
	r.printf("\nNook-managed containers: %d\n", len(live.Containers))
	if len(live.Containers) > 0 {
		r.table("ID\tNAME\tIMAGE\tSTATUS", func(w *tabwriter.Writer) {
			for _, c := range live.Containers {
				_, _ = fmt.Fprintf(w, "%.12s\t%s\t%s\t%s\n", c.ID, c.Name, c.Image, c.Status)
			}
		})
	}
}

type joinTokenInfo struct {
	ID        string     `json:"id"`
	Prefix    string     `json:"prefix"`
	MaxUses   int32      `json:"max_uses"`
	Uses      int32      `json:"uses"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

type createdJoinToken struct {
	Token       string        `json:"token"`
	Server      string        `json:"server"`
	CAHash      string        `json:"ca_hash"`
	JoinCommand string        `json:"join_command"`
	Metadata    joinTokenInfo `json:"metadata"`
}

func (r *runner) joinTokenCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "join-token", Short: "Create, list and revoke node join tokens"}
	var maxUses int32
	var expires time.Duration
	create := &cobra.Command{
		Use: "create", Short: "Create a join token and print the command to run on the new node", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			if expires != 0 && (expires < time.Minute || expires > 7*24*time.Hour) {
				return &usageError{errors.New("--expires must be between 1m and 168h")}
			}
			body := map[string]any{"max_uses": maxUses}
			if expires != 0 {
				body["expires_in_seconds"] = int64(expires.Seconds())
			}
			var tok createdJoinToken
			if err := c.do(cmd.Context(), http.MethodPost, "/api/v1/join-tokens", body, &tok); err != nil {
				return err
			}
			return r.emit(tok, func() {
				r.printf("Join token created (id %s): valid for %d join(s) until %s.\n\nOn the new node, run:\n\n  %s\n\n",
					tok.Metadata.ID, tok.Metadata.MaxUses, tok.Metadata.ExpiresAt.Local().Format(time.RFC1123), tok.JoinCommand)
				r.printf("The token is shown only now. The --ca-hash pins this installation's CA, so the agent\nwill not send the token to any other server.\n")
			})
		},
	}
	create.Flags().Int32Var(&maxUses, "max-uses", 1, "how many nodes may join with this token")
	create.Flags().DurationVar(&expires, "expires", 0, "token lifetime, e.g. 1h or 30m (default: the server's NOOK_JOIN_TOKEN_TTL)")

	list := &cobra.Command{
		Use: "list", Short: "List recent join tokens (never the secrets)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			items, err := fetchAll[joinTokenInfo](cmd, c, "/api/v1/join-tokens")
			if err != nil {
				return err
			}
			return r.emit(items, func() {
				r.table("ID\tPREFIX\tUSES\tEXPIRES\tSTATE", func(w *tabwriter.Writer) {
					for _, t := range items {
						state := "usable"
						switch {
						case t.RevokedAt != nil:
							state = "revoked"
						case time.Now().After(t.ExpiresAt):
							state = "expired"
						case t.Uses >= t.MaxUses:
							state = "used up"
						}
						_, _ = fmt.Fprintf(w, "%s\t%s…\t%d/%d\t%s\t%s\n", t.ID, t.Prefix, t.Uses, t.MaxUses, t.ExpiresAt.Local().Format("2006-01-02 15:04"), state)
					}
				})
			})
		},
	}
	revoke := &cobra.Command{
		Use: "revoke <token-id>", Short: "Revoke a join token", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := r.authed()
			if err != nil {
				return err
			}
			if err := c.do(cmd.Context(), http.MethodDelete, "/api/v1/join-tokens/"+url.PathEscape(args[0]), nil, nil); err != nil {
				return err
			}
			return r.emit(map[string]string{"revoked": args[0]}, func() { r.printf("Revoked join token %s.\n", args[0]) })
		},
	}
	cmd.AddCommand(create, list, revoke)
	return cmd
}
