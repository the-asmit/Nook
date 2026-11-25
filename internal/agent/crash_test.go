package agent

import (
	"testing"
	"time"
)

func TestCrashBackoffDoublesUpToTheMaximum(t *testing.T) {
	p := crashPolicy{Limit: 10, Window: time.Hour, MinBackoff: time.Second, MaxBackoff: 10 * time.Second}
	var h crashHistory
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	for i, w := range want {
		delay, giveUp, count := h.record(now, p)
		if giveUp || delay != w || count != i+1 {
			t.Fatalf("crash %d: delay %s giveUp %v count %d; want %s", i+1, delay, giveUp, count, w)
		}
		now = now.Add(delay + time.Second)
	}
}

func TestCrashLoopGivesUpAfterTheLimitWithinTheWindow(t *testing.T) {
	p := crashPolicy{Limit: 3, Window: time.Minute, MinBackoff: time.Second, MaxBackoff: time.Minute}
	var h crashHistory
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 3 {
		if _, giveUp, _ := h.record(now, p); giveUp {
			t.Fatalf("gave up after %d crashes", i+1)
		}
		now = now.Add(10 * time.Second)
	}
	if _, giveUp, count := h.record(now, p); !giveUp || count != 4 {
		t.Fatalf("4 crashes within a minute: giveUp %v count %d", giveUp, count)
	}
}

func TestCrashesOutsideTheWindowAreForgotten(t *testing.T) {
	p := crashPolicy{Limit: 2, Window: time.Minute, MinBackoff: time.Second, MaxBackoff: time.Minute}
	var h crashHistory
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for range 10 {
		delay, giveUp, count := h.record(now, p)
		if giveUp || count != 1 || delay != time.Second {
			t.Fatalf("isolated crash: delay %s giveUp %v count %d", delay, giveUp, count)
		}
		now = now.Add(2 * time.Minute) // each crash falls outside the previous window
	}
}

// fakeClock fires timers when the test advances it.
type fakeClock struct {
	now    time.Time
	timers []fakeTimer
}

type fakeTimer struct {
	at      time.Time
	f       func()
	stopped *bool
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) AfterFunc(d time.Duration, f func()) func() bool {
	stopped := false
	c.timers = append(c.timers, fakeTimer{at: c.now.Add(d), f: f, stopped: &stopped})
	return func() bool {
		was := !stopped
		stopped = true
		return was
	}
}

func (c *fakeClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
	var due []fakeTimer
	rest := c.timers[:0]
	for _, t := range c.timers {
		if !t.at.After(c.now) {
			due = append(due, t)
		} else {
			rest = append(rest, t)
		}
	}
	c.timers = rest
	for _, t := range due {
		if !*t.stopped {
			t.f()
		}
	}
}

func TestRestartSchedulerUsesTheBackoff(t *testing.T) {
	c := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	p := crashPolicy{Limit: 5, Window: time.Hour, MinBackoff: 2 * time.Second, MaxBackoff: time.Minute}
	s := &restartScheduler{clock: c, policy: p}
	restarted := 0
	gaveUp := false
	crash := func() {
		s.crashed(func() { restarted++ }, func(int) { gaveUp = true })
	}
	crash()
	c.advance(time.Second)
	if restarted != 0 {
		t.Fatal("restarted before the backoff")
	}
	c.advance(time.Second)
	if restarted != 1 {
		t.Fatalf("restarts after 2s = %d; want 1", restarted)
	}
	crash() // second crash: 4s
	c.advance(3 * time.Second)
	if restarted != 1 {
		t.Fatal("second restart came too early")
	}
	c.advance(time.Second)
	if restarted != 2 {
		t.Fatalf("restarts = %d; want 2", restarted)
	}
	crash()
	s.cancel() // a stop during the backoff cancels the restart
	c.advance(time.Minute)
	if restarted != 2 || gaveUp {
		t.Fatalf("restart after cancel: restarted %d gaveUp %v", restarted, gaveUp)
	}
	for range 3 {
		crash()
		c.advance(time.Minute)
	}
	if !gaveUp {
		t.Fatal("did not give up after 6 crashes within the window")
	}
}
