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
		var notReady notReadyError
		switch err := a.builder.start(kind.Build); { //nolint:contextcheck // see above
		case errors.Is(err, errBusy), errors.Is(err, errShuttingDown):
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_BUSY, err.Error())
		case errors.As(err, &notReady):
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, err.Error())
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
	case *agentv1.Command_StartInstance:
		if err := a.containersReady(); err != nil {
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, err.Error())
		}
		// The instance outlives the command: the manager owns its context.
		switch err := a.instances.start(kind.StartInstance); { //nolint:contextcheck // see above
		case errors.Is(err, errShuttingDown):
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_BUSY, err.Error())
		case err != nil:
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, "invalid start command: "+err.Error())
		}
		a.logger.InfoContext(ctx, "starting app instance", "instance", kind.StartInstance.GetInstanceId(), "app", kind.StartInstance.GetAppSlug())
		res.Result = accepted
	case *agentv1.Command_StopInstance:
		// The stop outlives the command (drain): the manager owns its context.
		if err := a.instances.stop(kind.StopInstance.GetInstanceId(), kind.StopInstance.GetDrain().AsDuration(), kind.StopInstance.GetKeepContainer()); err != nil { //nolint:contextcheck // see above
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, err.Error())
		}
		res.Result = accepted
	case *agentv1.Command_StreamLogs:
		// The stream outlives the command: the manager owns its context.
		switch err := a.instances.streamLogs(kind.StreamLogs); { //nolint:contextcheck // see above
		case errors.Is(err, errBusy), errors.Is(err, errShuttingDown):
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_BUSY, err.Error())
		case err != nil:
			return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, err.Error())
		}
		res.Result = accepted
	case *agentv1.Command_StopLogs:
		a.instances.stopLogs(kind.StopLogs.GetStreamId())
		res.Result = accepted
	default:
		if handled, msg := a.executeDatabase(ctx, cmd); handled {
			if msg != "" {
				return fail(agentv1.CommandErrorCode_COMMAND_ERROR_CODE_FAILED, msg)
			}
			res.Result = accepted
			break
		}
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
	case cmd.GetStartInstance() != nil:
		return "start_instance"
	case cmd.GetStopInstance() != nil:
		return "stop_instance"
	case cmd.GetStreamLogs() != nil:
		return "stream_logs"
	case cmd.GetStopLogs() != nil:
		return "stop_logs"
	case cmd.GetStartDatabase() != nil:
		return "start_database"
	case cmd.GetStopDatabase() != nil:
		return "stop_database"
	case cmd.GetBackupDatabase() != nil:
		return "backup_database"
	case cmd.GetDumpDatabase() != nil:
		return "dump_database"
	case cmd.GetUploadDump() != nil:
		return "upload_dump"
	case cmd.GetUpdateDatabaseTls() != nil:
		return "update_database_tls"
	case cmd.GetSetDatabaseEndpoint() != nil:
		return "set_database_endpoint"
	default:
		return "unknown"
	}
}

// executeDatabase runs the app database server's commands. It reports
// whether cmd was one of them and, if it failed, why. The long-running
// ones only start here (their results are reported later): the manager
// owns their context.
func (a *Agent) executeDatabase(ctx context.Context, cmd *agentv1.Command) (bool, string) {
	var err error
	switch kind := cmd.GetKind().(type) {
	case *agentv1.Command_StartDatabase:
		if err = a.databases.start(kind.StartDatabase); err == nil { //nolint:contextcheck // see above
			a.logger.InfoContext(ctx, "starting the app database server", "server", kind.StartDatabase.GetServerId(), "mode", kind.StartDatabase.GetMode())
		}
	case *agentv1.Command_StopDatabase:
		err = a.databases.stop(kind.StopDatabase) //nolint:contextcheck // see above
	case *agentv1.Command_BackupDatabase:
		err = a.databases.backup(kind.BackupDatabase) //nolint:contextcheck // see above
	case *agentv1.Command_DumpDatabase:
		err = a.databases.dump(kind.DumpDatabase) //nolint:contextcheck // see above
	case *agentv1.Command_UploadDump:
		err = a.databases.upload(kind.UploadDump) //nolint:contextcheck // see above
	case *agentv1.Command_UpdateDatabaseTls:
		err = a.databases.updateTLS(ctx, kind.UpdateDatabaseTls)
	case *agentv1.Command_SetDatabaseEndpoint:
		err = a.databases.setEndpoint(ctx, kind.SetDatabaseEndpoint.GetEndpoint())
	default:
		return false, ""
	}
	if err != nil {
		return true, err.Error()
	}
	return true, ""
}
