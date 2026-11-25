package builds

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"

	"github.com/the-asmit/nook/internal/objstore"
	"github.com/the-asmit/nook/internal/store"
)

// Build output travels through a Redis Stream per deployment. Agents'
// lines arrive at whichever control-plane instance holds their stream and
// are appended there; followers on any instance read the same stream, so
// a follower never needs to be on the agent's instance. When an attempt
// ends its lines are also stored as an object, which outlives the stream.

// Entry kinds in a log stream.
const (
	kindLine   = "l"
	kindNote   = "n"
	kindEnd    = "e"
	logMaxLen  = 300000
	liveTTL    = 7 * 24 * time.Hour
	endedTTL   = time.Hour
	maxLogRead = 64 << 20
)

func logKey(deploymentID uuid.UUID) string { return "nook:build-log:" + deploymentID.String() }

// LogObjectKey is where an attempt's log is stored.
func LogObjectKey(workspaceID, appID, deploymentID uuid.UUID, attempt int32) string {
	return fmt.Sprintf("logs/%s/%s/%s/%d.log", workspaceID, appID, deploymentID, attempt)
}

// Logs stores and serves build output.
type Logs struct {
	redis   *goredis.Client
	objects *objstore.Client
	store   *store.Store
	logger  *slog.Logger
}

// NewLogs returns the log service.
func NewLogs(rdb *goredis.Client, objects *objstore.Client, st *store.Store, logger *slog.Logger) *Logs {
	return &Logs{redis: rdb, objects: objects, store: st, logger: logger}
}

func (l *Logs) add(ctx context.Context, deploymentID uuid.UUID, buildID, kind string, texts ...string) error {
	key := logKey(deploymentID)
	_, err := l.redis.Pipelined(ctx, func(p goredis.Pipeliner) error {
		for _, t := range texts {
			p.XAdd(ctx, &goredis.XAddArgs{Stream: key, MaxLen: logMaxLen, Approx: true,
				Values: map[string]any{"k": kind, "b": buildID, "t": t}})
		}
		p.Expire(ctx, key, liveTTL)
		return nil
	})
	if err != nil {
		return fmt.Errorf("append build log: %w", err)
	}
	return nil
}

// Append adds an agent's lines for a build.
func (l *Logs) Append(ctx context.Context, deploymentID, buildID uuid.UUID, lines []string) error {
	return l.add(ctx, deploymentID, buildID.String(), kindLine, lines...)
}

// Output adds lines that are not from a build attempt (an app's output
// during its rollout).
func (l *Logs) Output(ctx context.Context, deploymentID uuid.UUID, lines []string) {
	if err := l.add(ctx, deploymentID, "", kindLine, lines...); err != nil {
		l.logger.WarnContext(ctx, "could not write deployment output", "error", err.Error())
	}
}

// Note adds a line written by Nook itself (attempt headers, retries).
func (l *Logs) Note(ctx context.Context, deploymentID uuid.UUID, buildID, text string) {
	if err := l.add(ctx, deploymentID, buildID, kindNote, "[nook] "+text); err != nil {
		l.logger.WarnContext(ctx, "could not write build log note", "error", err.Error())
	}
}

// End marks a deployment's log complete; followers stop after it.
func (l *Logs) End(ctx context.Context, deploymentID uuid.UUID, status store.DeploymentStatus) {
	key := logKey(deploymentID)
	_, err := l.redis.Pipelined(ctx, func(p goredis.Pipeliner) error {
		p.XAdd(ctx, &goredis.XAddArgs{Stream: key, MaxLen: logMaxLen, Approx: true,
			Values: map[string]any{"k": kindEnd, "b": "", "t": string(status)}})
		p.Expire(ctx, key, endedTTL)
		return nil
	})
	if err != nil {
		l.logger.WarnContext(ctx, "could not end build log", "error", err.Error())
	}
}

// Persist stores a finished attempt's output as an object.
func (l *Logs) Persist(ctx context.Context, workspaceID uuid.UUID, b *store.Build) error {
	entries, err := l.redis.XRange(ctx, logKey(b.DeploymentID), "-", "+").Result()
	if err != nil {
		return fmt.Errorf("read build log: %w", err)
	}
	var sb strings.Builder
	id := b.ID.String()
	for _, e := range entries {
		if e.Values["b"] == id {
			t, _ := e.Values["t"].(string)
			sb.WriteString(t)
			sb.WriteByte('\n')
		}
	}
	key := LogObjectKey(workspaceID, b.AppID, b.DeploymentID, b.Attempt)
	if err := l.objects.Put(ctx, key, "text/plain; charset=utf-8", []byte(sb.String())); err != nil {
		return err
	}
	if err := l.store.SetBuildLogKey(ctx, store.SetBuildLogKeyParams{ID: b.ID, LogKey: &key}); err != nil {
		return fmt.Errorf("record log key: %w", err)
	}
	return nil
}

// Read returns a deployment's complete log as text: from the live stream
// while it exists, otherwise from the stored objects.
func (l *Logs) Read(ctx context.Context, deploymentID uuid.UUID, builds []store.Build) (string, error) {
	entries, err := l.redis.XRange(ctx, logKey(deploymentID), "-", "+").Result()
	if err != nil {
		return "", fmt.Errorf("read build log: %w", err)
	}
	var sb strings.Builder
	if len(entries) > 0 {
		for _, e := range entries {
			if e.Values["k"] == kindEnd {
				continue
			}
			t, _ := e.Values["t"].(string)
			sb.WriteString(t)
			sb.WriteByte('\n')
		}
		return sb.String(), nil
	}
	for i := range builds {
		b := &builds[i]
		if b.LogKey == nil {
			fmt.Fprintf(&sb, "[nook] the log of attempt %d is no longer available\n", b.Attempt)
			continue
		}
		data, err := l.objects.Get(ctx, *b.LogKey, maxLogRead)
		if errors.Is(err, objstore.ErrNotFound) {
			fmt.Fprintf(&sb, "[nook] the log of attempt %d is no longer available\n", b.Attempt)
			continue
		}
		if err != nil {
			return "", err
		}
		sb.Write(data)
	}
	return sb.String(), nil
}

// Event is one item of a followed log.
type Event struct {
	// Type is "line", "status" or "end".
	Type string
	Text string
	// Status is set for "status" and "end".
	Status store.DeploymentStatus
}

// statusPoll is how often a follower re-reads the deployment status.
const statusPoll = 2 * time.Second

// Follow streams a deployment's log to emit as it is written, then a
// final "end" event once the deployment finished. It returns when the
// deployment ends, emit fails or ctx is done.
func (l *Logs) Follow(ctx context.Context, deploymentID uuid.UUID, emit func(Event) error) error {
	key := logKey(deploymentID)
	last := "0"
	var status store.DeploymentStatus
	lastPoll := time.Time{}
	terminalPolls := 0
	for ctx.Err() == nil {
		if time.Since(lastPoll) >= statusPoll {
			lastPoll = time.Now()
			d, err := l.store.GetDeploymentByID(ctx, deploymentID)
			if err != nil {
				return fmt.Errorf("read deployment: %w", err)
			}
			if d.Status != status {
				status = d.Status
				if err := emit(Event{Type: "status", Status: status}); err != nil {
					return err
				}
			}
			if Terminal(status) {
				terminalPolls++
			}
		}
		res, err := l.redis.XRead(ctx, &goredis.XReadArgs{Streams: []string{key, last}, Count: 500, Block: statusPoll}).Result()
		if ctxDone(ctx) {
			return nil // the follower went away
		}
		if err != nil && !errors.Is(err, goredis.Nil) {
			return fmt.Errorf("follow build log: %w", err)
		}
		read := 0
		for _, s := range res {
			for _, e := range s.Messages {
				last = e.ID
				read++
				t, _ := e.Values["t"].(string)
				if e.Values["k"] == kindEnd {
					return emit(Event{Type: "end", Status: store.DeploymentStatus(t)})
				}
				if err := emit(Event{Type: "line", Text: t}); err != nil {
					return err
				}
			}
		}
		// A finished deployment whose stream carries no end marker (it
		// expired, or Redis lost it): fall back to the stored log.
		if read == 0 && terminalPolls >= 2 {
			if last == "0" {
				builds, err := l.store.ListBuilds(ctx, deploymentID)
				if err != nil {
					return fmt.Errorf("list builds: %w", err)
				}
				text, err := l.Read(ctx, deploymentID, builds)
				if err != nil {
					return err
				}
				for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
					if line == "" {
						continue
					}
					if err := emit(Event{Type: "line", Text: line}); err != nil {
						return err
					}
				}
			}
			return emit(Event{Type: "end", Status: status})
		}
	}
	return nil
}

// Terminal reports whether a deployment status is final for its log: the
// deployment was released, will not be, or failed. (A built deployment
// waits for its rollout.)
func Terminal(s store.DeploymentStatus) bool {
	switch s {
	case store.DeploymentStatusFailed, store.DeploymentStatusCancelled, store.DeploymentStatusLive,
		store.DeploymentStatusSuperseded, store.DeploymentStatusRolledBack:
		return true
	default:
		return false
	}
}

// ctxDone reports whether ctx has ended.
func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
