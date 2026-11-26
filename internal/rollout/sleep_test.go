package rollout

import (
	"testing"
	"time"
)

// TestSleepDue: an app sleeps exactly when its sleep_after has passed
// since its last request (the leader's clock is injected).
func TestSleepDue(t *testing.T) {
	last := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	after := 15 * time.Minute
	for _, c := range []struct {
		now  time.Time
		want bool
	}{
		{last, false},
		{last.Add(after - time.Millisecond), false},
		{last.Add(after), true},
		{last.Add(after + time.Hour), true},
		{last.Add(-time.Minute), false}, // a request newer than the clock
	} {
		if got := SleepDue(last, after, c.now); got != c.want {
			t.Errorf("SleepDue(last, 15m, last%+v) = %v, want %v", c.now.Sub(last), got, c.want)
		}
	}
}
