package nodes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/store"
)

// Redis Pub/Sub channels. Names follow nook:<kind>:<subject>.
const (
	// EventsChannel carries every node state transition as an Event in
	// JSON. The scheduler of a later stage subscribes to it.
	EventsChannel = "nook:events:nodes"
	// ControlChannel tells every control-plane instance to act on a node,
	// e.g. to disconnect a removed node's agent.
	ControlChannel = "nook:control:nodes"
)

// Event is a node state transition as published on EventsChannel.
type Event struct {
	ID         uuid.UUID         `json:"id"`
	NodeID     uuid.UUID         `json:"node_id"`
	NodeName   string            `json:"node_name"`
	FromStatus *store.NodeStatus `json:"from_status"`
	ToStatus   store.NodeStatus  `json:"to_status"`
	Reason     string            `json:"reason"`
	At         time.Time         `json:"at"`
}

// ControlMessage is published on ControlChannel.
type ControlMessage struct {
	Action string    `json:"action"`
	NodeID uuid.UUID `json:"node_id"`
}

// ControlDisconnect asks the instance holding a node's stream to end it.
const ControlDisconnect = "disconnect"

// Publisher publishes node events and control messages.
type Publisher struct {
	redis *goredis.Client
}

// NewPublisher returns a publisher.
func NewPublisher(client *goredis.Client) *Publisher {
	return &Publisher{redis: client}
}

// Event publishes a transition. Publishing happens after the database
// commit; a lost message is tolerable because the database is the source
// of truth and subscribers resynchronize from it.
func (p *Publisher) Event(ctx context.Context, e *Event) error {
	return p.publish(ctx, EventsChannel, e)
}

// Control publishes a control message to every control-plane instance.
func (p *Publisher) Control(ctx context.Context, m ControlMessage) error {
	return p.publish(ctx, ControlChannel, m)
}

func (p *Publisher) publish(ctx context.Context, channel string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode %s message: %w", channel, err)
	}
	if err := p.redis.Publish(ctx, channel, data).Err(); err != nil {
		return fmt.Errorf("publish to %s: %w", channel, err)
	}
	return nil
}

// recordTransition writes a node event inside the transaction q and
// returns it for publishing once the transaction commits.
func recordTransition(ctx context.Context, q *store.Queries, nodeID uuid.UUID, name string, from *store.NodeStatus, to store.NodeStatus, reason string) (*Event, error) {
	row, err := q.InsertNodeEvent(ctx, store.InsertNodeEventParams{
		NodeID: nodeID, FromStatus: from, ToStatus: to, Reason: reason,
	})
	if err != nil {
		return nil, fmt.Errorf("record node event: %w", err)
	}
	return &Event{ID: row.ID, NodeID: nodeID, NodeName: name, FromStatus: from, ToStatus: to, Reason: reason, At: row.CreatedAt}, nil
}
