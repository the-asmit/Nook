package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Log streaming limits the agent applies whatever it is asked.
const (
	maxLogStreamBytes    = 1 << 30
	maxLogStreamDuration = 24 * time.Hour
	maxLogStreams        = 32
	appLogBatchLines     = 200
	appLogBatchDelay     = 100 * time.Millisecond
	maxStreamLineLength  = 16 << 10
)

var streamIDPattern = func(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// streamLogs starts sending an instance's output for a log stream.
func (m *instances) streamLogs(cmd *agentv1.StreamLogsCommand) error {
	if !streamIDPattern(cmd.GetStreamId()) || !buildIDPattern.MatchString(cmd.GetInstanceId()) {
		return errors.New("invalid log stream")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx == nil {
		return errShuttingDown
	}
	if _, ok := m.logs[cmd.GetStreamId()]; ok {
		return nil
	}
	if len(m.logs) >= maxLogStreams {
		return errBusy
	}
	limit := min(max(cmd.GetMaxDuration().AsDuration(), time.Second), maxLogStreamDuration)
	ctx, cancel := context.WithTimeout(m.ctx, limit)
	m.logs[cmd.GetStreamId()] = cancel
	m.wg.Go(func() {
		defer func() {
			cancel()
			m.mu.Lock()
			delete(m.logs, cmd.GetStreamId())
			m.mu.Unlock()
		}()
		msg := m.sendLogs(ctx, cmd)
		m.outbox.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_AppLog{AppLog: &agentv1.AppLog{
			StreamId: cmd.GetStreamId(), End: true, Message: msg,
		}}})
	})
	return nil
}

// stopLogs ends a log stream.
func (m *instances) stopLogs(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel, ok := m.logs[id]; ok {
		cancel()
	}
}

// sendLogs copies the container's output into AppLog messages and returns
// why it stopped ("" at the end of the output).
func (m *instances) sendLogs(ctx context.Context, cmd *agentv1.StreamLogsCommand) string {
	opts := client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Timestamps: true, Follow: cmd.GetFollow()}
	if cmd.GetTail() > 0 {
		opts.Tail = strconv.Itoa(int(cmd.GetTail()))
	}
	if cmd.GetSince() != nil {
		opts.Since = strconv.FormatInt(cmd.GetSince().AsTime().Unix(), 10)
	}
	rc, err := m.docker.client.ContainerLogs(ctx, containerName(cmd.GetInstanceId()), opts)
	if err != nil {
		return "the app's container is gone"
	}
	defer func() { _ = rc.Close() }()
	b := &logBatcher{id: cmd.GetStreamId(), outbox: m.outbox, limit: min(max(cmd.GetMaxBytes(), 1), maxLogStreamBytes)}
	stdout, stderr := b.writer("stdout"), b.writer("stderr")
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(appLogBatchDelay)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				b.flush()
			}
		}
	}()
	_, err = stdcopy.StdCopy(stdout, stderr, rc)
	stdout.end()
	stderr.end()
	b.flush()
	switch {
	case errors.Is(err, errLogLimit):
		return fmt.Sprintf("output truncated after %d bytes", b.limit)
	case errors.Is(context.Cause(ctx), context.DeadlineExceeded):
		return "the log stream reached its time limit"
	default:
		return ""
	}
}

var errLogLimit = errors.New("log size limit reached")

// logBatcher groups lines into AppLog messages and enforces the byte limit.
type logBatcher struct {
	id     string
	outbox *outbox
	limit  int64

	mu    sync.Mutex
	lines []*agentv1.LogLine
	sent  int64
}

func (b *logBatcher) add(stream, raw string) error {
	at, text := splitTimestamp(raw)
	if len(text) > maxStreamLineLength {
		text = text[:maxStreamLineLength]
	}
	b.mu.Lock()
	if b.sent+int64(len(text)) > b.limit {
		b.mu.Unlock()
		return errLogLimit
	}
	b.sent += int64(len(text))
	b.lines = append(b.lines, &agentv1.LogLine{Time: timestamppb.New(at), Stream: stream, Text: strings.ToValidUTF8(text, "?")})
	full := len(b.lines) >= appLogBatchLines
	b.mu.Unlock()
	if full {
		b.flush()
	}
	return nil
}

func (b *logBatcher) flush() {
	b.mu.Lock()
	lines := b.lines
	b.lines = nil
	b.mu.Unlock()
	if len(lines) > 0 {
		b.outbox.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_AppLog{AppLog: &agentv1.AppLog{StreamId: b.id, Lines: lines}}})
	}
}

// splitTimestamp separates Docker's RFC 3339 timestamp prefix from a line.
func splitTimestamp(raw string) (time.Time, string) {
	ts, text, ok := strings.Cut(raw, " ")
	if ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return t, text
		}
	}
	return time.Now(), raw
}

// lineWriter splits one output stream into lines for the batcher.
type lineWriter struct {
	b      *logBatcher
	stream string
	buf    bytes.Buffer
}

func (b *logBatcher) writer(stream string) *lineWriter { return &lineWriter{b: b, stream: stream} }

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			if w.buf.Len() > maxStreamLineLength*2 {
				line := w.buf.Next(maxStreamLineLength)
				if err := w.b.add(w.stream, string(line)); err != nil {
					return 0, err
				}
			}
			return len(p), nil
		}
		line := w.buf.Next(i + 1)
		if err := w.b.add(w.stream, strings.TrimRight(string(line), "\r\n")); err != nil {
			return 0, err
		}
	}
}

// end flushes a last line without a newline.
func (w *lineWriter) end() {
	if w.buf.Len() > 0 {
		_ = w.b.add(w.stream, w.buf.String())
		w.buf.Reset()
	}
}

var _ io.Writer = (*lineWriter)(nil)
