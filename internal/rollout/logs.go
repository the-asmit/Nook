package rollout

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/the-asmit/nook/internal/apperr"
	"github.com/the-asmit/nook/internal/store"
	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// Redis names used for app log streams.
//
//	nook:app-log:<stream>       stream: lines an agent sent for one `nook logs` request
//	nook:app-log:<stream>:node  string: the node allowed to write to it
func appLogKey(id string) string     { return "nook:app-log:" + id }
func appLogNodeKey(id string) string { return "nook:app-log:" + id + ":node" }

// Bounds on log streams.
const (
	maxLogLinesPerMessage = 1000
	maxLogLineLength      = 16 << 10
	appLogMaxLen          = 10000
	maxTail               = 10000
	logReadBlock          = 5 * time.Second
)

// LogOptions selects the output a client wants.
type LogOptions struct {
	Follow bool
	// Tail is the number of lines from the end (0: everything retained).
	Tail int32
	// Since limits output to lines after this time (zero: no limit).
	Since time.Time
}

// LogLine is one line of an app's output.
type LogLine struct {
	Time   time.Time `json:"time"`
	Stream string    `json:"stream"`
	Text   string    `json:"text"`
}

// LogStreams streams app container output from the node running it to a
// client connected to any control-plane instance: the agent sends lines
// over its Connect stream to the instance holding that stream, which
// appends them to a Redis stream the client's instance reads.
type LogStreams struct {
	redis     *goredis.Client
	commander Commander
	cfg       Config
	logger    *slog.Logger
}

// NewLogStreams returns the log streamer.
func NewLogStreams(rdb *goredis.Client, commander Commander, cfg *Config, logger *slog.Logger) *LogStreams {
	return &LogStreams{redis: rdb, commander: commander, cfg: *cfg, logger: logger}
}

// Stream sends inst's output to emit until it ends (without Follow), the
// size or duration limit is reached, emit fails or ctx is done.
func (l *LogStreams) Stream(ctx context.Context, inst *store.AppInstance, opts LogOptions, emit func(LogLine) error) error {
	if inst.NodeID == nil {
		return apperr.Unavailable("logs_unavailable", "the app's node was removed; its logs are gone")
	}
	if opts.Tail < 0 || opts.Tail > maxTail {
		return apperr.Invalid("invalid_tail", "tail must be between 0 and %d", maxTail)
	}
	ctx, cancel := context.WithTimeout(ctx, l.cfg.LogMaxDuration+time.Minute)
	defer cancel()
	id := strings.ReplaceAll(uuid.NewV4().String(), "-", "")
	if err := l.redis.Set(ctx, appLogNodeKey(id), inst.NodeID.String(), l.cfg.LogMaxDuration+2*time.Minute).Err(); err != nil {
		return fmt.Errorf("register log stream: %w", err)
	}
	cmd := &agentv1.StreamLogsCommand{
		StreamId: id, InstanceId: inst.ID.String(), Follow: opts.Follow, Tail: opts.Tail,
		MaxBytes: l.cfg.LogMaxBytes, MaxDuration: durationpb.New(l.cfg.LogMaxDuration),
	}
	if !opts.Since.IsZero() {
		cmd.Since = timestamppb.New(opts.Since)
	}
	defer l.close(context.WithoutCancel(ctx), *inst.NodeID, id)
	res, err := l.commander.Dispatch(ctx, *inst.NodeID, &agentv1.Command{Kind: &agentv1.Command_StreamLogs{StreamLogs: cmd}}, dispatchTimeout)
	if err != nil {
		return err
	}
	if e := res.GetError(); e != nil {
		return apperr.Unavailable("logs_unavailable", "node %s cannot read the app's logs: %s", inst.NodeName, sanitize(e.GetMessage()))
	}
	last := "0"
	for {
		res, err := l.redis.XRead(ctx, &goredis.XReadArgs{Streams: []string{appLogKey(id), last}, Count: 500, Block: logReadBlock}).Result()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && !errors.Is(err, goredis.Nil) {
			return fmt.Errorf("read log stream: %w", err)
		}
		for _, s := range res {
			for _, e := range s.Messages {
				last = e.ID
				text, _ := e.Values["x"].(string)
				if e.Values["k"] == "end" {
					if text != "" {
						return emit(LogLine{Time: time.Now().UTC(), Stream: "nook", Text: text})
					}
					return nil
				}
				stream, _ := e.Values["s"].(string)
				ts, _ := e.Values["t"].(string)
				at, _ := time.Parse(time.RFC3339Nano, ts)
				if err := emit(LogLine{Time: at, Stream: stream, Text: text}); err != nil {
					return err
				}
			}
		}
	}
}

// close tells the agent to stop sending and drops the stream.
func (l *LogStreams) close(ctx context.Context, nodeID uuid.UUID, id string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, _ = l.commander.Dispatch(ctx, nodeID, &agentv1.Command{Kind: &agentv1.Command_StopLogs{StopLogs: &agentv1.StopLogsCommand{StreamId: id}}}, 3*time.Second)
	if err := l.redis.Del(ctx, appLogKey(id), appLogNodeKey(id)).Err(); err != nil {
		l.logger.WarnContext(ctx, "could not delete a log stream", "error", err.Error())
	}
}

// AppLog appends lines an agent sent for a log stream. Lines for streams
// the node was not asked for are dropped.
func (l *LogStreams) AppLog(ctx context.Context, nodeID uuid.UUID, m *agentv1.AppLog) error {
	id := m.GetStreamId()
	if len(id) != 32 {
		return nil
	}
	owner, err := l.redis.Get(ctx, appLogNodeKey(id)).Result()
	if errors.Is(err, goredis.Nil) || (err == nil && owner != nodeID.String()) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check log stream: %w", err)
	}
	lines := m.GetLines()
	if len(lines) > maxLogLinesPerMessage {
		lines = lines[:maxLogLinesPerMessage]
	}
	key := appLogKey(id)
	_, err = l.redis.Pipelined(ctx, func(p goredis.Pipeliner) error {
		for _, ln := range lines {
			text := ln.GetText()
			if len(text) > maxLogLineLength {
				text = text[:maxLogLineLength]
			}
			stream := "stdout"
			if ln.GetStream() == "stderr" {
				stream = "stderr"
			}
			p.XAdd(ctx, &goredis.XAddArgs{Stream: key, MaxLen: appLogMaxLen, Approx: true, Values: map[string]any{
				"k": "line", "s": stream, "t": ln.GetTime().AsTime().UTC().Format(time.RFC3339Nano), "x": strings.ToValidUTF8(text, "?"),
			}})
		}
		if m.GetEnd() {
			p.XAdd(ctx, &goredis.XAddArgs{Stream: key, MaxLen: appLogMaxLen, Approx: true, Values: map[string]any{
				"k": "end", "x": sanitize(m.GetMessage()),
			}})
		}
		p.Expire(ctx, key, l.cfg.LogMaxDuration+2*time.Minute)
		return nil
	})
	if err != nil {
		return fmt.Errorf("append app log: %w", err)
	}
	return nil
}
