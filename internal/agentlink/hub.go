// Package agentlink is the control plane's side of the gRPC link to node
// agents: the mTLS gRPC server (Join, Connect, RenewCertificate) and the
// hub that tracks connected agents and routes commands to them, across
// control-plane instances.
package agentlink

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/nodes"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Redis names used by the hub.
//
//	nook:node:<id>:instance         string: ID of the instance holding the node's stream
//	nook:agent-commands:<instance>  channel: commands to forward to agents on <instance>
//	nook:command-results:<instance> channel: results for commands <instance> dispatched
func ownerKey(nodeID uuid.UUID) string       { return "nook:node:" + nodeID.String() + ":instance" }
func commandsChannel(instance string) string { return "nook:agent-commands:" + instance }
func resultsChannel(instance string) string  { return "nook:command-results:" + instance }

// resultGrace is extra time the dispatcher waits beyond a command's own
// timeout, for the result to travel back.
const resultGrace = 2 * time.Second

// sessionQueue bounds messages waiting to be sent to one agent.
const sessionQueue = 64

// Errors a dispatcher can return, already classified for the API.
var (
	ErrNodeNotConnected  = apperr.Unavailable("node_not_connected", "the node's agent is not connected")
	ErrAgentDisconnected = apperr.Unavailable("agent_disconnected", "the node's agent disconnected before answering")
	ErrCommandTimeout    = apperr.Timeout("command_timeout", "the node's agent did not answer in time")
)

// Hub tracks the agents connected to this instance and routes commands to
// agents connected to any instance through Redis.
type Hub struct {
	instance string
	redis    *goredis.Client
	ownerTTL time.Duration
	logger   *slog.Logger

	mu       sync.Mutex
	sessions map[uuid.UUID]*session
	pending  map[string]chan *agentv1.CommandResult
	ready    chan struct{}
}

// NewHub returns a hub for this instance. ownerTTL is how long the record
// "node X is connected here" survives without a heartbeat refreshing it.
func NewHub(instance string, client *goredis.Client, ownerTTL time.Duration, logger *slog.Logger) *Hub {
	return &Hub{
		instance: instance, redis: client, ownerTTL: ownerTTL, logger: logger,
		sessions: map[uuid.UUID]*session{}, pending: map[string]chan *agentv1.CommandResult{},
		ready: make(chan struct{}),
	}
}

// Instance returns this control-plane instance's ID.
func (h *Hub) Instance() string { return h.instance }

// session is one connected agent stream on this instance.
type session struct {
	nodeID uuid.UUID
	send   chan *agentv1.ConnectResponse
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu       sync.Mutex
	inflight map[string]inflightCommand // by command ID
}

// inflightCommand is a command delivered to the agent and not yet answered.
type inflightCommand struct {
	replyTo string // instance waiting for the result
	// expires is when the waiting instance has given up, so an agent that
	// never answers cannot grow the map without bound.
	expires time.Time
}

// prune drops commands whose caller has given up. s.mu must be held.
func (s *session) prune(now time.Time) {
	for id, c := range s.inflight {
		if now.After(c.expires) {
			delete(s.inflight, id)
		}
	}
}

// envelopes exchanged over Redis Pub/Sub.
type commandEnvelope struct {
	NodeID  uuid.UUID `json:"node_id"`
	ReplyTo string    `json:"reply_to"`
	Command []byte    `json:"command"`
}

type resultEnvelope struct {
	CommandID string `json:"command_id"`
	Result    []byte `json:"result"`
}

// Run subscribes to this instance's channels and the node control channel
// and handles their messages until ctx is done.
func (h *Hub) Run(ctx context.Context) error {
	sub := h.redis.Subscribe(ctx, commandsChannel(h.instance), resultsChannel(h.instance), nodes.ControlChannel)
	defer func() { _ = sub.Close() }()
	// Wait for the subscription to be confirmed before advertising
	// ourselves, so no command published to us can be missed.
	if _, err := sub.Receive(ctx); err != nil {
		return fmt.Errorf("subscribe to hub channels: %w", err)
	}
	close(h.ready)
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-ch:
			if !ok {
				return errors.New("hub subscription closed")
			}
			h.handle(ctx, msg)
		}
	}
}

// Ready is closed once the hub receives messages.
func (h *Hub) Ready() <-chan struct{} { return h.ready }

func (h *Hub) handle(ctx context.Context, msg *goredis.Message) {
	switch msg.Channel {
	case commandsChannel(h.instance):
		var env commandEnvelope
		if err := json.Unmarshal([]byte(msg.Payload), &env); err != nil {
			h.logger.WarnContext(ctx, "drop malformed command envelope", "error", err.Error())
			return
		}
		h.deliver(ctx, &env)
	case resultsChannel(h.instance):
		var env resultEnvelope
		if err := json.Unmarshal([]byte(msg.Payload), &env); err != nil {
			h.logger.WarnContext(ctx, "drop malformed result envelope", "error", err.Error())
			return
		}
		var res agentv1.CommandResult
		if err := proto.Unmarshal(env.Result, &res); err != nil {
			return
		}
		h.mu.Lock()
		wait, ok := h.pending[env.CommandID]
		delete(h.pending, env.CommandID)
		h.mu.Unlock()
		if ok {
			wait <- &res // buffered: never blocks
		}
	case nodes.ControlChannel:
		var m nodes.ControlMessage
		if err := json.Unmarshal([]byte(msg.Payload), &m); err != nil || m.Action != nodes.ControlDisconnect {
			return
		}
		h.mu.Lock()
		s := h.sessions[m.NodeID]
		h.mu.Unlock()
		if s != nil {
			s.cancel(nodes.ErrNodeRemoved)
		}
	}
}

// deliver forwards a command to a locally connected agent, or answers at
// once that the agent is gone.
func (h *Hub) deliver(ctx context.Context, env *commandEnvelope) {
	var cmd agentv1.Command
	if err := proto.Unmarshal(env.Command, &cmd); err != nil {
		return
	}
	h.mu.Lock()
	s := h.sessions[env.NodeID]
	h.mu.Unlock()
	if s == nil {
		h.reply(ctx, env.ReplyTo, failure(cmd.GetCommandId(), "the agent is no longer connected to this control-plane instance"))
		return
	}
	now := time.Now()
	s.mu.Lock()
	s.prune(now)
	s.inflight[cmd.GetCommandId()] = inflightCommand{replyTo: env.ReplyTo, expires: now.Add(cmd.GetTimeout().AsDuration() + time.Second)}
	s.mu.Unlock()
	select {
	case s.send <- &agentv1.ConnectResponse{Message: &agentv1.ConnectResponse_Command{Command: &cmd}}:
	default:
		s.mu.Lock()
		delete(s.inflight, cmd.GetCommandId())
		s.mu.Unlock()
		h.reply(ctx, env.ReplyTo, failure(cmd.GetCommandId(), "the agent's command queue is full"))
	}
}

func failure(commandID, msg string) *agentv1.CommandResult {
	return &agentv1.CommandResult{CommandId: commandID, Result: &agentv1.CommandResult_Error{
		Error: &agentv1.CommandError{Code: agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, Message: msg},
	}}
}

// disconnectedMarker tags results synthesized because the stream ended.
const disconnectedMarker = "agent disconnected"

func (h *Hub) reply(ctx context.Context, instance string, res *agentv1.CommandResult) {
	data, err := proto.Marshal(res)
	if err != nil {
		return
	}
	payload, err := json.Marshal(resultEnvelope{CommandID: res.GetCommandId(), Result: data})
	if err != nil {
		return
	}
	if err := h.redis.Publish(ctx, resultsChannel(instance), payload).Err(); err != nil {
		h.logger.WarnContext(ctx, "publish command result", "error", err.Error())
	}
}

// Dispatch sends cmd to a node's agent wherever it is connected and waits
// for its single result. It sets the command ID and, if unset, the timeout.
func (h *Hub) Dispatch(ctx context.Context, nodeID uuid.UUID, cmd *agentv1.Command, timeout time.Duration) (*agentv1.CommandResult, error) {
	owner, err := h.redis.Get(ctx, ownerKey(nodeID)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, ErrNodeNotConnected
	}
	if err != nil {
		return nil, fmt.Errorf("find node's control-plane instance: %w", err)
	}
	cmd.CommandId = rand.Text()
	cmd.Timeout = durationpb.New(timeout)
	data, err := proto.Marshal(cmd)
	if err != nil {
		return nil, fmt.Errorf("encode command: %w", err)
	}
	payload, err := json.Marshal(commandEnvelope{NodeID: nodeID, ReplyTo: h.instance, Command: data})
	if err != nil {
		return nil, fmt.Errorf("encode command envelope: %w", err)
	}

	wait := make(chan *agentv1.CommandResult, 1)
	h.mu.Lock()
	h.pending[cmd.CommandId] = wait
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, cmd.CommandId)
		h.mu.Unlock()
	}()

	receivers, err := h.redis.Publish(ctx, commandsChannel(owner), payload).Result()
	if err != nil {
		return nil, fmt.Errorf("send command: %w", err)
	}
	if receivers == 0 {
		// The owning instance is gone; its record has not expired yet.
		return nil, ErrNodeNotConnected
	}

	timer := time.NewTimer(timeout + resultGrace)
	defer timer.Stop()
	select {
	case res := <-wait:
		if e := res.GetError(); e != nil && e.GetMessage() == disconnectedMarker {
			return nil, ErrAgentDisconnected
		}
		return res, nil
	case <-timer.C:
		return nil, ErrCommandTimeout
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for command result: %w", ctx.Err())
	}
}

// register records a new stream for nodeID on this instance, replacing
// (and ending) any older stream of the same node.
func (h *Hub) register(ctx context.Context, nodeID uuid.UUID) (*session, error) {
	sctx, cancel := context.WithCancelCause(ctx)
	s := &session{nodeID: nodeID, send: make(chan *agentv1.ConnectResponse, sessionQueue), ctx: sctx, cancel: cancel, inflight: map[string]inflightCommand{}}
	h.mu.Lock()
	old := h.sessions[nodeID]
	h.sessions[nodeID] = s
	h.mu.Unlock()
	if old != nil {
		old.cancel(errReplaced)
	}
	if err := h.redis.Set(ctx, ownerKey(nodeID), h.instance, h.ownerTTL).Err(); err != nil {
		h.unregister(context.WithoutCancel(ctx), s)
		return nil, fmt.Errorf("record node connection: %w", err)
	}
	return s, nil
}

var errReplaced = errors.New("replaced by a newer connection from the same node")

// touch refreshes the record of where a node is connected.
func (h *Hub) touch(ctx context.Context, nodeID uuid.UUID) error {
	if err := h.redis.Set(ctx, ownerKey(nodeID), h.instance, h.ownerTTL).Err(); err != nil {
		return fmt.Errorf("refresh node connection: %w", err)
	}
	return nil
}

// compareAndDelete removes the owner record only if it still names us, so
// a node that already reconnected elsewhere keeps its new record.
var compareAndDelete = goredis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) end
return 0`)

// unregister ends a session and fails every command still waiting on it.
func (h *Hub) unregister(ctx context.Context, s *session) {
	h.mu.Lock()
	current := h.sessions[s.nodeID] == s
	if current {
		delete(h.sessions, s.nodeID)
	}
	h.mu.Unlock()
	s.cancel(context.Canceled)
	if current {
		if err := compareAndDelete.Run(ctx, h.redis, []string{ownerKey(s.nodeID)}, h.instance).Err(); err != nil {
			h.logger.WarnContext(ctx, "clear node connection", "error", err.Error())
		}
	}
	s.mu.Lock()
	inflight := s.inflight
	s.inflight = map[string]inflightCommand{}
	s.mu.Unlock()
	for id, c := range inflight {
		h.reply(ctx, c.replyTo, failure(id, disconnectedMarker))
	}
}

// complete routes a command result from an agent to the waiting instance.
func (h *Hub) complete(ctx context.Context, s *session, res *agentv1.CommandResult) {
	s.mu.Lock()
	c, ok := s.inflight[res.GetCommandId()]
	delete(s.inflight, res.GetCommandId())
	s.mu.Unlock()
	if ok {
		h.reply(ctx, c.replyTo, res)
	}
}

// closeAll ends every local session, e.g. at shutdown.
func (h *Hub) closeAll(cause error) {
	h.mu.Lock()
	sessions := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.mu.Unlock()
	for _, s := range sessions {
		s.cancel(cause)
	}
}
