package agent

import (
	"context"
	"errors"
	"time"

	agentv1 "github.com/the-asmit/nook/proto/nook/agent/v1"
)

// maxCommandTimeout caps what the control plane may ask for.
const maxCommandTimeout = 5 * time.Minute

// execute runs one command within its timeout and returns its result.
// Build commands only start the build; its outcome is reported later.
func (a *Agent) execute(ctx context.Context, cmd *agentv1.Command) *agentv1.CommandResult {
	timeout := min(max(cmd.GetTimeout().AsDuration(), time.Second), maxCommandTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := &agentv1.CommandResult{CommandId: cmd.GetCommandId()}
	fail := func(code agentv1.CommandErrorCode, msg string) *agentv1.CommandResult {
		res.Result = &agentv1.CommandResult_Error{Error: &agentv1.CommandError{Code: code, Message: msg}}
		a.metrics.commands.WithLabelValues(kindOf(cmd), "error").Inc()
		return res
	}
	accepted := &agentv1.CommandResult_Accepted{Accepted: &agentv1.Accepted{}}
	switch kind := cmd.GetKind().(type) {
	case *agentv1.Command_InspectNode:
		out, err := a.docker.inspect(ctx)
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_TIMEOUT, "inspection did not finish in "+timeout.String())
		case err != nil:
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_DOCKER_UNAVAILABLE, err.Error())
		}
		res.Result = &agentv1.CommandResult_InspectNode{InspectNode: out}
	case *agentv1.Command_Build:
		// A build outlives the command that starts it: the builder owns its context.
		switch err := a.builder.start(kind.Build); { //nolint:contextcheck // see above
		case errors.Is(err, errBusy), errors.Is(err, errShuttingDown):
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_BUSY, err.Error())
		case err != nil:
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, "invalid build command: "+err.Error())
		}
		a.logger.InfoContext(ctx, "build started", "build_id", kind.Build.GetBuildId(), "attempt", kind.Build.GetAttempt())
		res.Result = accepted
	case *agentv1.Command_CancelBuild:
		if !a.builder.cancelBuild(kind.CancelBuild.GetBuildId()) {
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, "no such build is running on this node")
		}
		res.Result = accepted
	default:
		return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_UNSUPPORTED, "this agent does not support the command; upgrade nook-agent")
	}
	a.metrics.commands.WithLabelValues(kindOf(cmd), "ok").Inc()
	return res
}

func kindOf(cmd *agentv1.Command) string {
	switch {
	case cmd.GetInspectNode() != nil:
		return "inspect_node"
	case cmd.GetBuild() != nil:
		return "build"
	case cmd.GetCancelBuild() != nil:
		return "cancel_build"
	default:
		return "unknown"
	}
}
