package builds

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	goredis "github.com/redis/go-redis/v9"
)

// Redis keys and channels of the build pipeline (see docs/architecture.md).
const (
	// queueStream holds one entry per build job (field "d": deployment ID).
	queueStream = "nook:builds:queue"
	// queueGroup is the consumer group every control-plane instance joins;
	// each instance is one consumer named after its instance ID.
	queueGroup = "dispatchers"
	// wakeChannel carries deployment IDs whose owner should look again now.
	wakeChannel = "nook:builds:wake"
	// queueMaxLen trims the stream (approximately); acknowledged entries
	// are history only.
	queueMaxLen = 100000
)

func ownerKey(id uuid.UUID) string { return "nook:builds:owner:" + id.String() }

// Queue adds build jobs and wakes their owners. It is the side of the
// pipeline the API uses.
type Queue struct {
	redis *goredis.Client
}

// NewQueue returns a queue on client.
func NewQueue(client *goredis.Client) *Queue {
	return &Queue{redis: client}
}

// Enqueue adds a job for a deployment. Jobs are idempotent: a duplicate
// for a deployment that is already handled is acknowledged and dropped.
func (q *Queue) Enqueue(ctx context.Context, deploymentID uuid.UUID) error {
	err := q.redis.XAdd(ctx, &goredis.XAddArgs{
		Stream: queueStream, MaxLen: queueMaxLen, Approx: true,
		Values: map[string]any{"d": deploymentID.String()},
	}).Err()
	if err != nil {
		return fmt.Errorf("enqueue build: %w", err)
	}
	return nil
}

// Wake asks the instance handling a deployment to re-check it now. Best
// effort: owners also re-check periodically.
func (q *Queue) Wake(ctx context.Context, deploymentID uuid.UUID) {
	_ = q.redis.Publish(ctx, wakeChannel, deploymentID.String()).Err()
}

// ensureGroup creates the stream and the consumer group if needed.
func ensureGroup(ctx context.Context, rdb *goredis.Client) error {
	err := rdb.XGroupCreateMkStream(ctx, queueStream, queueGroup, "0").Err()
	if err != nil && !strings.HasPrefix(err.Error(), "BUSYGROUP") {
		return fmt.Errorf("create consumer group: %w", err)
	}
	return nil
}

// job is one stream entry.
type job struct {
	entryID      string
	deploymentID uuid.UUID
	valid        bool
}

func toJobs(msgs []goredis.XMessage) []job {
	out := make([]job, 0, len(msgs))
	for _, m := range msgs {
		raw, _ := m.Values["d"].(string)
		id, err := uuid.Parse(raw)
		out = append(out, job{entryID: m.ID, deploymentID: id, valid: err == nil})
	}
	return out
}

// reclaim takes over jobs that another (presumably dead) consumer left
// unacknowledged for longer than minIdle.
func reclaim(ctx context.Context, rdb *goredis.Client, consumer string, minIdle time.Duration) ([]job, error) {
	msgs, _, err := rdb.XAutoClaim(ctx, &goredis.XAutoClaimArgs{
		Stream: queueStream, Group: queueGroup, Consumer: consumer, MinIdle: minIdle, Start: "0-0", Count: 32,
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("reclaim jobs: %w", err)
	}
	return toJobs(msgs), nil
}

// readNew blocks up to block for new jobs.
func readNew(ctx context.Context, rdb *goredis.Client, consumer string, block time.Duration, count int64) ([]job, error) {
	streams, err := rdb.XReadGroup(ctx, &goredis.XReadGroupArgs{
		Group: queueGroup, Consumer: consumer, Streams: []string{queueStream, ">"}, Count: count, Block: block,
	}).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read jobs: %w", err)
	}
	var out []job
	for _, s := range streams {
		out = append(out, toJobs(s.Messages)...)
	}
	return out, nil
}

// ack acknowledges a job: it is done (or was a duplicate).
func ack(ctx context.Context, rdb *goredis.Client, entryID string) error {
	if err := rdb.XAck(ctx, queueStream, queueGroup, entryID).Err(); err != nil {
		return fmt.Errorf("ack job: %w", err)
	}
	return nil
}

// touch resets a pending job's idle time, telling other instances that
// its consumer is alive and still working on it.
func touch(ctx context.Context, rdb *goredis.Client, consumer, entryID string) error {
	return rdb.XClaimJustID(ctx, &goredis.XClaimArgs{
		Stream: queueStream, Group: queueGroup, Consumer: consumer, MinIdle: 0, Messages: []string{entryID},
	}).Err()
}

// acquireOwner makes this instance the owner of a deployment, unless a
// live instance already is.
func acquireOwner(ctx context.Context, rdb *goredis.Client, id uuid.UUID, instance string) (bool, error) {
	ok, err := rdb.SetNX(ctx, ownerKey(id), instance, ownerTTL).Result()
	if err != nil {
		return false, fmt.Errorf("acquire owner lock: %w", err)
	}
	return ok, nil
}

var renewScript = goredis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("PEXPIRE", KEYS[1], ARGV[2]) end
return 0`)

var releaseScript = goredis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) end
return 0`)

// renewOwner extends the lock; false means ownership was lost.
func renewOwner(ctx context.Context, rdb *goredis.Client, id uuid.UUID, instance string) (bool, error) {
	n, err := renewScript.Run(ctx, rdb, []string{ownerKey(id)}, instance, ownerTTL.Milliseconds()).Int()
	if err != nil {
		return false, fmt.Errorf("renew owner lock: %w", err)
	}
	return n == 1, nil
}

func releaseOwner(ctx context.Context, rdb *goredis.Client, id uuid.UUID, instance string) {
	_ = releaseScript.Run(ctx, rdb, []string{ownerKey(id)}, instance).Err()
}

// hasOwner reports whether some instance currently owns a deployment.
func hasOwner(ctx context.Context, rdb *goredis.Client, id uuid.UUID) (bool, error) {
	n, err := rdb.Exists(ctx, ownerKey(id)).Result()
	if err != nil {
		return false, fmt.Errorf("check owner lock: %w", err)
	}
	return n == 1, nil
}
