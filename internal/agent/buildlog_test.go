package agent

import (
	"strings"
	"testing"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

func drain(o *outbox) (lines, finished []string) {
	for _, m := range o.take() {
		lines = append(lines, m.GetBuildLog().GetLines()...)
		if f := m.GetBuildFinished(); f != nil {
			finished = append(finished, f.GetBuildId())
		}
	}
	return lines, finished
}

func TestLogStreamSplitsBatchesAndTruncates(t *testing.T) {
	out := newOutbox()
	l := newLogStream("b1", out, 40)
	_, _ = l.Write([]byte("first line\r\nsecond "))
	_, _ = l.Write([]byte("line\nthird"))
	l.flushPartial()
	lines, _ := drain(out)
	if strings.Join(lines, "|") != "first line|second line|third" {
		t.Fatalf("lines %q", lines)
	}
	l.line(strings.Repeat("x", 30))
	l.line("dropped")
	l.flush()
	lines, _ = drain(out)
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "[nook] log truncated") {
		t.Fatalf("after the limit: %q", lines)
	}
	if l.total() <= 40 {
		t.Fatalf("total %d does not count dropped output", l.total())
	}
}

func TestLogStreamRecognizesRegistryErrors(t *testing.T) {
	l := newLogStream("b", newOutbox(), 1<<20)
	l.line("#8 exporting to image")
	if l.mentionsAfterError("registry:5000", "ws/app/cache") {
		t.Fatal("no error yet")
	}
	// The cache of an app's first build does not exist yet: not a push
	// failure, so the user's own error below stays the user's.
	l.line("#4 ERROR: failed to configure registry cache importer: registry:5000/ws/app/cache:buildcache: not found")
	l.line(`error: failed to solve: process "/bin/sh -c false" did not complete successfully: exit code: 1`)
	if l.mentionsAfterError("registry:5000", "ws/app/cache") {
		t.Fatal("a missing build cache was taken for a push failure")
	}
	l.line("ERROR: failed to push registry:5000/ws/app:b-1: unexpected status 401")
	if !l.mentionsAfterError("registry:5000", "ws/app/cache") {
		t.Fatal("push error not recognized")
	}
}

func TestOutboxKeepsOrderAcrossRequeue(t *testing.T) {
	o := newOutbox()
	for _, id := range []string{"a", "b", "c"} {
		o.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_BuildFinished{BuildFinished: &agentv1.BuildFinished{BuildId: id}}})
	}
	items := o.take()
	o.push(&agentv1.ConnectRequest{Message: &agentv1.ConnectRequest_BuildFinished{BuildFinished: &agentv1.BuildFinished{BuildId: "d"}}})
	o.requeue(items[1:])
	if got := o.pendingResults(); strings.Join(got, "") != "bcd" {
		t.Fatalf("pending %v", got)
	}
	if o.empty() {
		t.Fatal("empty")
	}
	_, finished := drain(o)
	if strings.Join(finished, "") != "bcd" || !o.empty() {
		t.Fatalf("drained %v", finished)
	}
}
