package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// This file implements the io.modelcontextprotocol/tasks extension:
// campaign/start (async task creation), tasks/get, tasks/cancel, and
// tasks/update. The methods map the campaign engine's persisted state onto
// task results; the engine itself stays protocol-agnostic.

// taskState mirrors the fields of the engine's persisted campaign state
// that the tasks/* handlers need. It is parsed from the engine's JSON
// (StatusFromJSON) so the protocol layer does not import the engine
// package; the mirror is deliberately small and additive-field tolerant.
type taskState struct {
	WorkflowID      string               `json:"workflow_id"`
	Status          string               `json:"status"` // running|paused|cancelled|completed|failed
	Error           string               `json:"error,omitempty"`
	NextIndex       int                  `json:"next_index"`
	Steps           []json.RawMessage    `json:"steps"`
	FinalResult     json.RawMessage      `json:"final_result,omitempty"`
	PendingApproval *taskPendingApproval `json:"pending_approval,omitempty"`
	MITRE           []string             `json:"techniques,omitempty"`
}

// taskPendingApproval mirrors the engine's PendingApproval checkpoint
// field: an approval gate that paused a task-tracked campaign.
type taskPendingApproval struct {
	Tool      string          `json:"tool"`
	StepID    string          `json:"step_id"`
	RequestID string          `json:"request_id"`
	Message   string          `json:"message,omitempty"`
	Response  json.RawMessage `json:"response,omitempty"`
	Resolved  string          `json:"resolved,omitempty"` // approved|denied once answered
}

// handleCampaignStart implements campaign/start. Without the tasks
// extension it is exactly campaign/run (synchronous). With the tasks
// extension declared in the request's _meta, the campaign is started
// asynchronously and a CreateTaskResult is returned immediately.
func (s *Server) handleCampaignStart(ctx context.Context, req *JSONRPCRequest) *JSONRPCResponse {
	if s.campaign == nil {
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, "campaign engine not configured")
	}
	if !TasksExtensionEnabled(ctx) {
		// Capability not declared: fail closed to the synchronous
		// semantics of campaign/run.
		return s.handleCampaignRun(ctx, req)
	}

	// The background run must not be tied to the request's lifetime, but
	// it must keep the request's context values (auth identity, and the
	// tasks-extension marker itself) so every step runs through the full
	// middleware chain with the caller's identity and can elicit approval
	// instead of failing. WithoutCancel drops exactly the cancellation and
	// deadline, preserving values. Async campaigns are intentionally not
	// bounded by the request-level workflow timeout; each step is still
	// bounded by the execution middleware's per-tool timeout.
	runCtx := context.WithoutCancel(ctx)
	taskID, alreadyRunning, err := s.campaign.StartAsyncFromJSON(runCtx, req.Params)
	if err != nil {
		return s.errorResponse(req.ID, ErrCodeInternal, err.Error())
	}
	_ = alreadyRunning // both paths answer with the live task; status "working"
	return s.successResponse(req.ID, createTaskResult(taskID))
}

// createTaskResult builds the CreateTaskResult for a running task. The
// task id is the workflow id, so tasks/get, tasks/cancel, campaign/status
// and campaign/cancel all address the same object.
func createTaskResult(taskID string) CreateTaskResult {
	return CreateTaskResult{
		ResultType: ResultTypeTask,
		Task: TaskRef{
			TaskID:         taskID,
			Status:         TaskStatusWorking,
			TTLMs:          TaskTTLMS,
			PollIntervalMs: TaskPollIntervalMS,
		},
	}
}

// handleTasksGet maps a campaign's persisted state onto a task status.
func (s *Server) handleTasksGet(req *JSONRPCRequest) *JSONRPCResponse {
	if s.campaign == nil {
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, "campaign engine not configured")
	}
	var params TasksGetParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.TaskID == "" {
		return s.errorResponse(req.ID, ErrCodeInvalidParams, "tasks/get params require a taskId")
	}

	raw, err := s.campaign.StatusFromJSON(mustMarshalJSON(map[string]string{"workflow_id": params.TaskID}))
	if err != nil {
		// Unknown (or unreadable) task id: invalid params, per the tasks
		// extension's error contract.
		return s.errorResponse(req.ID, ErrCodeInvalidParams, fmt.Sprintf("unknown taskId %q", params.TaskID))
	}
	var state taskState
	if err := json.Unmarshal(raw, &state); err != nil {
		return s.errorResponse(req.ID, ErrCodeInternal, fmt.Sprintf("unreadable state for task %q", params.TaskID))
	}
	return s.successResponse(req.ID, taskResultFromState(&state))
}

// taskResultFromState maps campaign state onto the task lifecycle.
func taskResultFromState(state *taskState) GetTaskResult {
	switch state.Status {
	case "running":
		return GetTaskResult{Status: TaskStatusWorking}
	case "paused":
		if pa := state.PendingApproval; pa != nil {
			// A pending approval gate holds the task in input_required
			// until the operator answers via tasks/update and the
			// campaign is resumed.
			result := GetTaskResult{
				Status: TaskStatusInputRequired,
				InputRequests: map[string]InputRequest{
					ApprovalInputKey: {
						Type:      InputRequestTypeElicitation,
						Message:   approvalPromptMessage(pa.Tool),
						RequestID: pa.RequestID,
					},
				},
			}
			if pa.Resolved != "" {
				result.StatusMessage = fmt.Sprintf("approval response recorded (%s); resume with campaign/resume", pa.Resolved)
			} else {
				result.StatusMessage = fmt.Sprintf("step %s awaits operator approval for tool %q", pa.StepID, pa.Tool)
			}
			return result
		}
		return GetTaskResult{
			Status:        TaskStatusWorking,
			StatusMessage: fmt.Sprintf("paused at step %d; resumable", state.NextIndex),
		}
	case "completed":
		return GetTaskResult{
			Status: TaskStatusCompleted,
			Result: completedTaskResult(state),
		}
	case "failed":
		message := state.Error
		if message == "" {
			message = "campaign failed"
		}
		return GetTaskResult{
			Status: TaskStatusFailed,
			Error:  &JSONRPCError{Code: ErrCodeTaskFailed, Message: message},
		}
	case "cancelled":
		return GetTaskResult{Status: TaskStatusCancelled}
	default:
		return GetTaskResult{
			Status:        TaskStatusWorking,
			StatusMessage: fmt.Sprintf("campaign status %q", state.Status),
		}
	}
}

// completedTaskResult returns the persisted final WorkflowResult. Campaigns
// completed before the FinalResult field existed (or hand-edited states)
// get a result synthesized from the persisted state, preserving the
// campaign/run output shape.
func completedTaskResult(state *taskState) json.RawMessage {
	if len(state.FinalResult) > 0 {
		return state.FinalResult
	}
	synthesized := struct {
		WorkflowID string            `json:"workflow_id,omitempty"`
		Status     string            `json:"status,omitempty"`
		Steps      []json.RawMessage `json:"steps"`
		Success    bool              `json:"success"`
		MITRE      []string          `json:"mitre_techniques,omitempty"`
	}{
		WorkflowID: state.WorkflowID,
		Status:     "completed",
		Steps:      state.Steps,
		Success:    true,
		MITRE:      state.MITRE,
	}
	if synthesized.Steps == nil {
		synthesized.Steps = []json.RawMessage{}
	}
	data, err := json.Marshal(synthesized)
	if err != nil {
		return json.RawMessage(`{"status":"completed","success":true}`)
	}
	return data
}

// approvalPromptMessage builds the elicitation message for an approval
// gate on the named tool.
func approvalPromptMessage(tool string) string {
	return fmt.Sprintf("Tool %q requires operator approval. Review its full capabilities, then approve or deny this call.", tool)
}

// handleTasksCancel delegates to the engine's campaign cancel.
func (s *Server) handleTasksCancel(req *JSONRPCRequest) *JSONRPCResponse {
	if s.campaign == nil {
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, "campaign engine not configured")
	}
	var params TasksCancelParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.TaskID == "" {
		return s.errorResponse(req.ID, ErrCodeInvalidParams, "tasks/cancel params require a taskId")
	}

	if err := s.cancelTask(params.TaskID); err != nil {
		return s.errorResponse(req.ID, ErrCodeInvalidParams, err.Error())
	}
	// Empty-result ack, per the tasks extension.
	return s.successResponse(req.ID, struct{}{})
}

// cancelTask cancels the task named by taskId. Unknown tasks are invalid
// params; cancelling a task already in a terminal state is an idempotent
// no-op ack (the engine's Cancel would otherwise error on "already
// completed").
func (s *Server) cancelTask(taskID string) error {
	_, err := s.campaign.CancelFromJSON(mustMarshalJSON(map[string]string{"workflow_id": taskID}))
	if err == nil {
		return nil
	}
	if _, statusErr := s.campaign.StatusFromJSON(mustMarshalJSON(map[string]string{"workflow_id": taskID})); statusErr != nil {
		return fmt.Errorf("unknown taskId %q", taskID)
	}
	// The task exists; Cancel failed because it is already terminal
	// (completed/failed/cancelled). Treat as an idempotent no-op.
	return nil
}

// handleTasksUpdate records client inputResponses on a paused campaign's
// pending approval request. Unknown task ids are invalid params; unknown
// or stale response keys are acknowledged and ignored (spec).
func (s *Server) handleTasksUpdate(req *JSONRPCRequest) *JSONRPCResponse {
	if s.campaign == nil {
		return s.errorResponse(req.ID, ErrCodeMethodNotFound, "campaign engine not configured")
	}
	var params TasksUpdateParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.TaskID == "" {
		return s.errorResponse(req.ID, ErrCodeInvalidParams, "tasks/update params require a taskId")
	}

	payload, err := json.Marshal(map[string]any{
		"taskId":         params.TaskID,
		"inputResponses": params.InputResponses,
	})
	if err != nil {
		return s.errorResponse(req.ID, ErrCodeInternal, err.Error())
	}
	result, err := s.campaign.TaskUpdateFromJSON(payload)
	if err != nil {
		return s.errorResponse(req.ID, ErrCodeInvalidParams, err.Error())
	}
	return &JSONRPCResponse{JSONRPC: JSONRPCVersion, ID: req.ID, Result: json.RawMessage(result)}
}

// mustMarshalJSON is a tiny helper for building engine params; the inputs
// are constructed inline and always marshal.
func mustMarshalJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return data
}
