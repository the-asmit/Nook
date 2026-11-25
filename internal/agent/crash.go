package agent

import (
	"sync"
	"time"
)

// crashPolicy decides how a crashed app container is restarted: after an
// exponential backoff, and not at all once it crashed more than Limit
// times within Window (a crash loop). Docker's own restart policy is not
// used: the agent needs to see every crash to report it and to stop
// restarting a container that will never come up.
type crashPolicy struct {
	Limit  int
	Window time.Duration
	// MinBackoff is the delay before the first restart; each further
	// crash within the window doubles it, up to MaxBackoff.
	MinBackoff time.Duration
	MaxBackoff time.Duration
}

// crashHistory is the crash times of one instance within the window.
type crashHistory struct {
	times []time.Time
}

// record notes a crash at now and returns how long to wait before
// restarting, or giveUp when the instance crashed too often. count is the
// number of crashes within the window, including this one. Time comes
// from the caller so tests control it.
func (h *crashHistory) record(now time.Time, p crashPolicy) (delay time.Duration, giveUp bool, count int) {
	cutoff := now.Add(-p.Window)
	kept := h.times[:0]
	for _, t := range h.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	h.times = kept
	count = len(h.times)
	if count > p.Limit {
		return 0, true, count
	}
	delay = p.MinBackoff
	for i := 1; i < count && delay < p.MaxBackoff; i++ {
		delay *= 2
	}
	return min(delay, p.MaxBackoff), false, count
}

// clock lets tests replace time.
type clock interface {
	Now() time.Time
	// AfterFunc runs f after d; the returned function cancels it.
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) AfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}

// restartScheduler applies a crashPolicy to one instance.
type restartScheduler struct {
	clock  clock
	policy crashPolicy

	mu      sync.Mutex
	history crashHistory
	stop    func() bool
}

// crashed records a crash and either schedules restart after the backoff
// or calls giveUp with the number of crashes in the window. It returns the
// delay and count for reporting.
func (s *restartScheduler) crashed(restart func(), giveUp func(count int)) (delay time.Duration, count int) {
	s.mu.Lock()
	delay, stop, count := s.history.record(s.clock.Now(), s.policy)
	if !stop {
		s.stop = s.clock.AfterFunc(delay, restart)
	}
	s.mu.Unlock()
	if stop {
		giveUp(count)
	}
	return delay, count
}

// cancel drops a scheduled restart.
func (s *restartScheduler) cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		s.stop()
		s.stop = nil
	}
}
