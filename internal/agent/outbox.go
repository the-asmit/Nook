package agent

import (
	"sync"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// outbox holds build output and results until they have been sent on a
// Connect stream. Builds keep running while the agent reconnects; what
// they produce in the meantime is delivered, in order, on the next stream.
type outbox struct {
	mu    sync.Mutex
	items []*agentv1.ConnectRequest
	ready chan struct{}
}

func newOutbox() *outbox {
	return &outbox{ready: make(chan struct{}, 1)}
}

func (o *outbox) signal() {
	select {
	case o.ready <- struct{}{}:
	default:
	}
}

// push appends a message.
func (o *outbox) push(m *agentv1.ConnectRequest) {
	o.mu.Lock()
	o.items = append(o.items, m)
	o.mu.Unlock()
	o.signal()
}

// take removes and returns everything queued.
func (o *outbox) take() []*agentv1.ConnectRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	items := o.items
	o.items = nil
	return items
}

// requeue puts unsent messages back at the front, keeping their order.
func (o *outbox) requeue(unsent []*agentv1.ConnectRequest) {
	if len(unsent) == 0 {
		return
	}
	o.mu.Lock()
	o.items = append(append([]*agentv1.ConnectRequest(nil), unsent...), o.items...)
	o.mu.Unlock()
	o.signal()
}

// pendingResults returns the IDs of builds whose BuildFinished has not
// been sent yet.
func (o *outbox) pendingResults() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var ids []string
	for _, m := range o.items {
		if f := m.GetBuildFinished(); f != nil {
			ids = append(ids, f.GetBuildId())
		}
	}
	return ids
}

func (o *outbox) empty() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.items) == 0
}
