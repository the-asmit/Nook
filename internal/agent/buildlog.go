package agent

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Log streaming limits.
const (
	// logBatchLines and logBatchDelay bound how long a line waits before
	// it is sent: whichever comes first.
	logBatchLines = 100
	logBatchDelay = 200 * time.Millisecond
	// maxLineBytes truncates single pathological lines.
	maxLineBytes = 4096
	// recentLines are kept (even past the size limit) to classify failures.
	recentLines = 40
)

// logStream turns build output into BuildLog messages: complete lines,
// batched, capped at a total size, delivered through the outbox.
type logStream struct {
	id  string
	out *outbox
	max int64

	mu        sync.Mutex
	partial   []byte
	pending   []string
	written   int64
	produced  int64
	truncated bool
	recent    []string
	timer     *time.Timer
}

func newLogStream(id string, out *outbox, maxBytes int64) *logStream {
	return &logStream{id: id, out: out, max: maxBytes}
}

// Write receives raw output (it implements io.Writer for stdcopy).
func (l *logStream) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.partial = append(l.partial, p...)
	for {
		i := bytes.IndexByte(l.partial, '\n')
		if i < 0 {
			break
		}
		l.addLocked(string(bytes.TrimRight(l.partial[:i], "\r")))
		l.partial = l.partial[i+1:]
	}
	if len(l.partial) > maxLineBytes {
		l.addLocked(string(l.partial))
		l.partial = nil
	}
	return len(p), nil
}

// line adds one line of the agent's own commentary.
func (l *logStream) line(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addLocked(s)
}

func (l *logStream) addLocked(s string) {
	if len(s) > maxLineBytes {
		s = s[:maxLineBytes] + "…"
	}
	l.produced += int64(len(s)) + 1
	l.recent = append(l.recent, s)
	if len(l.recent) > recentLines {
		l.recent = l.recent[len(l.recent)-recentLines:]
	}
	if l.truncated {
		return
	}
	if l.written+int64(len(s))+1 > l.max {
		l.truncated = true
		l.pending = append(l.pending, "[nook] log truncated after "+strconv.FormatInt(l.written, 10)+" bytes")
		return
	}
	l.written += int64(len(s)) + 1
	l.pending = append(l.pending, s)
	switch {
	case len(l.pending) >= logBatchLines:
		l.flushLocked()
	case l.timer == nil:
		l.timer = time.AfterFunc(logBatchDelay, l.flush)
	}
}

// flush sends pending lines now.
func (l *logStream) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushLocked()
}

// flushPartial sends an unterminated last line and everything pending.
func (l *logStream) flushPartial() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.partial) > 0 {
		l.addLocked(string(l.partial))
		l.partial = nil
	}
	l.flushLocked()
}

func (l *logStream) flushLocked() {
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	if len(l.pending) == 0 {
		return
	}
	l.out.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_BuildLog{BuildLog: &agentv1.BuildLog{BuildId: l.id, Lines: l.pending}}})
	l.pending = nil
}

// total is the number of bytes of output produced, including any dropped
// beyond the limit.
func (l *logStream) total() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.produced
}

// mentionsAfterError reports whether one of the last lines is an error
// mentioning s (BuildKit names the registry when a push fails). Lines that
// also mention except (the build-cache repository) do not count: a cache
// that is not there yet ("failed to configure registry cache importer:
// ... not found" on an app's first build) or fails to export never fails
// a build, so it must not turn the user's own error into a retried
// "push failure".
func (l *logStream) mentionsAfterError(s, except string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.recent {
		lower := strings.ToLower(line)
		if except != "" && strings.Contains(line, except) {
			continue
		}
		if strings.Contains(lower, "error") && strings.Contains(line, s) {
			return true
		}
	}
	return false
}
