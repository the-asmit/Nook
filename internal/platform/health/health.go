// Package health probes the dependencies a binary needs (databases, caches)
// for readiness endpoints and for waiting on them at startup.
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Probe reports whether a dependency is reachable. It must return promptly
// once ctx is done.
type Probe func(ctx context.Context) error

// Check is a named probe, e.g. "postgres".
type Check struct {
	Name  string
	Probe Probe
}

// Result is the outcome of one check; Err is nil when it passed.
type Result struct {
	Name string
	Err  error
}

// Report is the outcome of running a set of checks, in the order given.
type Report struct {
	Results []Result
}

// Healthy reports whether every check passed.
func (r Report) Healthy() bool {
	return len(r.Failing()) == 0
}

// Failing returns the names of the checks that failed.
func (r Report) Failing() []string {
	var names []string
	for _, res := range r.Results {
		if res.Err != nil {
			names = append(names, res.Name)
		}
	}
	return names
}

// Run executes all checks concurrently, each bounded by timeout, so one
// hung dependency cannot delay the verdict on the others.
func Run(ctx context.Context, timeout time.Duration, checks ...Check) Report {
	results := make([]Result, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Go(func() {
			results[i] = Result{Name: c.Name, Err: runOne(ctx, timeout, c)}
		})
	}
	wg.Wait()
	return Report{Results: results}
}

func runOne(ctx context.Context, timeout time.Duration, c Check) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := c.Probe(ctx); err != nil {
		return fmt.Errorf("%s: %w", c.Name, err)
	}
	return nil
}

// Backoff controls how WaitUntil retries.
type Backoff struct {
	// Initial is the delay after the first failed attempt; it doubles up to Max.
	Initial time.Duration
	// Max caps the delay between attempts.
	Max time.Duration
	// AttemptTimeout bounds each individual probe.
	AttemptTimeout time.Duration
}

// DefaultBackoff suits waiting for a database or cache at process startup.
var DefaultBackoff = Backoff{Initial: 250 * time.Millisecond, Max: 2 * time.Second, AttemptTimeout: 5 * time.Second}

// WaitUntil retries check until it passes or ctx is done. It exists so a
// service started at the same moment as its database (docker compose,
// Kubernetes) waits briefly instead of crash-looping.
func WaitUntil(ctx context.Context, logger *slog.Logger, check Check, b Backoff) error {
	delay := b.Initial
	for attempt := 1; ; attempt++ {
		err := runOne(ctx, b.AttemptTimeout, check)
		if err == nil {
			if attempt > 1 {
				logger.InfoContext(ctx, "dependency is reachable", "dependency", check.Name, "attempts", attempt)
			}
			return nil
		}
		logger.WarnContext(ctx, "dependency not reachable yet; retrying",
			"dependency", check.Name, "attempt", attempt, "retry_in", delay.String(), "error", err.Error())

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for %s: %w", check.Name, errors.Join(ctx.Err(), err))
		case <-timer.C:
		}
		delay = min(delay*2, b.Max)
	}
}
