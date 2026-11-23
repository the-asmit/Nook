package health

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

var errDown = errors.New("down")

func ok(context.Context) error { return nil }

func failing(context.Context) error { return errDown }

// hang blocks until its context is done, like a dependency that accepts
// the connection but never answers.
func hang(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestRunReportsEachCheck(t *testing.T) {
	r := Run(context.Background(), time.Second,
		Check{Name: "a", Probe: ok},
		Check{Name: "b", Probe: failing},
		Check{Name: "c", Probe: ok},
	)
	if r.Healthy() {
		t.Fatal("report should not be healthy")
	}
	if got := r.Failing(); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("Failing() = %v, want [b]", got)
	}
	if !errors.Is(r.Results[1].Err, errDown) || r.Results[0].Err != nil {
		t.Fatalf("results = %+v", r.Results)
	}
}

func TestRunBoundsHungChecksByTimeout(t *testing.T) {
	r := Run(context.Background(), 20*time.Millisecond,
		Check{Name: "slow", Probe: hang},
		Check{Name: "fast", Probe: ok},
	)
	if got := r.Failing(); !slices.Equal(got, []string{"slow"}) {
		t.Fatalf("Failing() = %v, want [slow]", got)
	}
	if !errors.Is(r.Results[0].Err, context.DeadlineExceeded) {
		t.Fatalf("slow check error = %v, want deadline exceeded", r.Results[0].Err)
	}
}

func TestRunWithNoChecksIsHealthy(t *testing.T) {
	if !Run(context.Background(), time.Second).Healthy() {
		t.Fatal("empty report should be healthy")
	}
}

var quietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestWaitUntilRetriesUntilSuccess(t *testing.T) {
	var calls atomic.Int32
	probe := func(context.Context) error {
		if calls.Add(1) < 3 {
			return errDown
		}
		return nil
	}
	b := Backoff{Initial: time.Millisecond, Max: 2 * time.Millisecond, AttemptTimeout: time.Second}
	if err := WaitUntil(context.Background(), quietLogger, Check{Name: "x", Probe: probe}, b); err != nil {
		t.Fatalf("WaitUntil() = %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("probe called %d times, want 3", calls.Load())
	}
}

func TestWaitUntilStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	probe := func(context.Context) error {
		if calls.Add(1) == 2 {
			cancel()
		}
		return errDown
	}
	b := Backoff{Initial: time.Millisecond, Max: time.Millisecond, AttemptTimeout: time.Second}
	err := WaitUntil(ctx, quietLogger, Check{Name: "x", Probe: probe}, b)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, errDown) {
		t.Fatalf("WaitUntil() = %v, want both context.Canceled and the probe error", err)
	}
}
