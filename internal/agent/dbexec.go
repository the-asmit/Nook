package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

// execResult is how a command run in a container ended.
type execResult struct {
	Code int
	// Stderr is the end of the command's error output (bounded).
	Stderr string
}

// maxExecStderr bounds the error output kept from a command.
const maxExecStderr = 16 << 10

// exec runs cmd in a running container. stdin (may be nil) is sent and
// closed; stdout receives the command's output (nil: discarded). It
// returns once the command exited, or ctx ended.
func (d *docker) exec(ctx context.Context, containerID string, cmd []string, stdin io.Reader, stdout io.Writer) (execResult, error) {
	created, err := d.client.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		Cmd: cmd, AttachStdin: stdin != nil, AttachStdout: true, AttachStderr: true,
	})
	if err != nil {
		return execResult{}, fmt.Errorf("create exec: %w", err)
	}
	attached, err := d.client.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return execResult{}, fmt.Errorf("attach exec: %w", err)
	}
	defer attached.Close()
	// Closing the connection when ctx ends unblocks the copies below.
	stop := context.AfterFunc(ctx, attached.Close)
	defer stop()
	if stdin != nil {
		go func() {
			_, _ = io.Copy(attached.Conn, stdin)
			_ = attached.CloseWrite()
		}()
	}
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := &tailBuffer{max: maxExecStderr}
	if _, err = stdcopy.StdCopy(stdout, stderr, attached.Reader); err != nil && ctx.Err() == nil && !errors.Is(err, io.EOF) {
		return execResult{}, fmt.Errorf("read exec output: %w", err)
	}
	if ctx.Err() != nil {
		return execResult{}, ctx.Err()
	}
	// The output ended; the exit code is set a moment later.
	for {
		inspected, inspectErr := d.client.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
		if inspectErr != nil {
			return execResult{}, fmt.Errorf("inspect exec: %w", inspectErr)
		}
		if !inspected.Running {
			return execResult{Code: inspected.ExitCode, Stderr: strings.TrimSpace(stderr.String())}, nil
		}
		select {
		case <-ctx.Done():
			return execResult{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if over := len(t.b) - t.max; over > 0 {
		t.b = t.b[over:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.b) }
