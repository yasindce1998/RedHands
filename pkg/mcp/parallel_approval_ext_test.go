package mcp_test

// Full-stack tests for MRTR approval gating inside campaign parallel
// groups: a group whose sub-steps trip approval gates pauses the task
// once with one inputRequest per gated sub-step (keyed
// "approval-<subStepID>"); tasks/update answers each individually; and
// campaign/resume replays only the gated sub-steps. Reuses the
// taskTestServer harness from tasks_ext_test.go (real approval
// middleware + real campaign engine through the app-layer adapter).

import (
	"encoding/json"
	"testing"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// groupPauseRequests polls a task to input_required and returns its
// per-sub-step approval inputRequests keyed "approval-<subStepID>".
func groupPauseRequests(t *testing.T, ts *taskTestServer, taskID string) map[string]mcp.InputRequest {
	t.Helper()
	obj := ts.pollTaskStatus(t, taskID, mcp.TaskStatusInputRequired)
	var taskResult struct {
		InputRequests map[string]mcp.InputRequest `json:"inputRequests"`
	}
	if err := json.Unmarshal(mustJSON(t, obj), &taskResult); err != nil {
		t.Fatalf("input_required task must carry inputRequests: %v", obj)
	}
	if len(taskResult.InputRequests) == 0 {
		t.Fatalf("input_required task must carry inputRequests: %v", obj)
	}
	for key, req := range taskResult.InputRequests {
		if key == mcp.ApprovalInputKey {
			t.Fatalf("group pause must not use the sequential %q key: %v", mcp.ApprovalInputKey, taskResult.InputRequests)
		}
		if req.Type != mcp.InputRequestTypeElicitation || req.RequestID == "" || req.Message == "" {
			t.Fatalf("inputRequest %q = %+v", key, req)
		}
	}
	return taskResult.InputRequests
}

// TestMRTRParallelGroupApprovalFlow: a parallel group with one plain and
// two gated sub-steps pauses once with two per-sub-step inputRequests;
// after tasks/update approves both, campaign/resume completes the run
// with the plain sub-step executed exactly once and each approved
// sub-step executed exactly once more.
func TestMRTRParallelGroupApprovalFlow(t *testing.T) {
	ts := newTaskTestServer(t)

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"pgrp-1","steps":[{"id":"grp","parallel":[`+
			`{"id":"sub_safe","tool":"safe_tool"},`+
			`{"id":"sub_a","tool":"dangerous_tool"},`+
			`{"id":"sub_b","tool":"dangerous_tool"}]},`+
			`{"id":"after","tool":"safe_tool"}]}`))

	requests := groupPauseRequests(t, ts, "pgrp-1")
	reqA, okA := requests[mcp.GroupApprovalInputKey("sub_a")]
	reqB, okB := requests[mcp.GroupApprovalInputKey("sub_b")]
	if !okA || !okB {
		t.Fatalf("group inputRequests = %+v", requests)
	}
	if reqA.RequestID == reqB.RequestID {
		t.Fatalf("gated sub-steps must carry distinct request ids: %+v", requests)
	}
	if _, ok := requests[mcp.GroupApprovalInputKey("sub_safe")]; ok {
		t.Fatalf("non-gated sub-step must not carry an inputRequest: %+v", requests)
	}
	if runs := ts.dangerous.runs(); runs != 0 {
		t.Fatalf("gated sub-steps must not execute before approval, ran %d times", runs)
	}
	if runs := ts.safe.runs(); runs != 1 {
		t.Fatalf("plain sub-step must have run once, ran %d times", runs)
	}

	// Approve both gates in a single tasks/update, keyed per sub-step.
	ack := ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"pgrp-1","inputResponses":{`+
			`"approval-sub_a":{"approved":true,"requestId":"`+reqA.RequestID+`"},`+
			`"approval-sub_b":{"approved":true,"requestId":"`+reqB.RequestID+`"}}}`))
	if ack.Error != nil {
		t.Fatalf("tasks/update: %+v", ack.Error)
	}

	resume := ts.call(t, mcp.MethodCampaignResume, json.RawMessage(`{"workflow_id":"pgrp-1"}`))
	if resume.Error != nil {
		t.Fatalf("campaign/resume: %+v", resume.Error)
	}
	var resumed struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(mustJSON(t, resume.Result), &resumed); err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "completed" {
		t.Fatalf("resumed campaign status = %q, want completed", resumed.Status)
	}
	if runs := ts.dangerous.runs(); runs != 2 {
		t.Fatalf("approved sub-steps must each execute exactly once, ran %d times", runs)
	}
	// sub_safe + the after step.
	if runs := ts.safe.runs(); runs != 2 {
		t.Fatalf("plain sub-step must not re-execute (1 run) plus after step (1 run), ran %d times", runs)
	}
}

// TestMRTRParallelGroupApproveSomeDenySome: approving one gate and denying
// the other in one tasks/update completes the group under on_fail:
// continue; the denied sub-step never executes and is recorded as failed.
func TestMRTRParallelGroupApproveSomeDenySome(t *testing.T) {
	ts := newTaskTestServer(t)

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"pgrp-mixed","steps":[{"id":"grp","on_fail":"continue","parallel":[`+
			`{"id":"sub_a","tool":"dangerous_tool"},`+
			`{"id":"sub_b","tool":"dangerous_tool"}]},`+
			`{"id":"after","tool":"safe_tool"}]}`))

	requests := groupPauseRequests(t, ts, "pgrp-mixed")
	reqA := requests[mcp.GroupApprovalInputKey("sub_a")]

	ack := ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"pgrp-mixed","inputResponses":{`+
			`"approval-sub_a":{"approved":true,"requestId":"`+reqA.RequestID+`"},`+
			`"approval-sub_b":{"approved":false}}}`))
	if ack.Error != nil {
		t.Fatalf("tasks/update: %+v", ack.Error)
	}

	resume := ts.call(t, mcp.MethodCampaignResume, json.RawMessage(`{"workflow_id":"pgrp-mixed"}`))
	if resume.Error != nil {
		t.Fatalf("campaign/resume: %+v", resume.Error)
	}
	ts.pollTaskStatus(t, "pgrp-mixed", mcp.TaskStatusCompleted)
	if runs := ts.dangerous.runs(); runs != 1 {
		t.Fatalf("only the approved sub-step must execute, ran %d times", runs)
	}
	if runs := ts.safe.runs(); runs != 1 {
		t.Fatalf("step after the group must run once, ran %d times", runs)
	}
}

// TestMRTRParallelGroupDeniedFailsTask: denying every gate of a group
// with the default on_fail fails the campaign and the task.
func TestMRTRParallelGroupDeniedFailsTask(t *testing.T) {
	ts := newTaskTestServer(t)

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"pgrp-deny","steps":[{"id":"grp","parallel":[`+
			`{"id":"sub_a","tool":"dangerous_tool"}]},`+
			`{"id":"after","tool":"safe_tool"}]}`))

	groupPauseRequests(t, ts, "pgrp-deny")
	ack := ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"pgrp-deny","inputResponses":{"approval-sub_a":{"approved":false}}}`))
	if ack.Error != nil {
		t.Fatalf("tasks/update: %+v", ack.Error)
	}
	ts.call(t, mcp.MethodCampaignResume, json.RawMessage(`{"workflow_id":"pgrp-deny"}`))

	obj := ts.pollTaskStatus(t, "pgrp-deny", mcp.TaskStatusFailed)
	var taskResult struct {
		Error *mcp.JSONRPCError `json:"error"`
	}
	if err := json.Unmarshal(mustJSON(t, obj), &taskResult); err != nil {
		t.Fatal(err)
	}
	if taskResult.Error == nil || taskResult.Error.Code != mcp.ErrCodeTaskFailed {
		t.Fatalf("failed task error = %+v", taskResult.Error)
	}
	if runs := ts.dangerous.runs(); runs != 0 {
		t.Fatal("denied sub-step must never execute")
	}
	if runs := ts.safe.runs(); runs != 0 {
		t.Fatal("steps after a denied on_fail:stop group must not run")
	}
}

// TestMRTRParallelGroupCancelWhilePaused: tasks/cancel on a task paused
// inside a group cancels it; the pause record survives so a later
// campaign/resume (after tasks/update) finishes the run.
func TestMRTRParallelGroupCancelWhilePaused(t *testing.T) {
	ts := newTaskTestServer(t)

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"pgrp-cancel","steps":[{"id":"grp","parallel":[`+
			`{"id":"sub_safe","tool":"safe_tool"},`+
			`{"id":"sub_a","tool":"dangerous_tool"}]},`+
			`{"id":"after","tool":"safe_tool"}]}`))

	requests := groupPauseRequests(t, ts, "pgrp-cancel")
	reqA := requests[mcp.GroupApprovalInputKey("sub_a")]

	ack := ts.call(t, mcp.MethodTasksCancel, json.RawMessage(`{"taskId":"pgrp-cancel"}`))
	if ack.Error != nil {
		t.Fatalf("tasks/cancel: %+v", ack.Error)
	}
	ts.pollTaskStatus(t, "pgrp-cancel", mcp.TaskStatusCancelled)

	// Answer the gate, then resume from the cancelled checkpoint.
	ack = ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"pgrp-cancel","inputResponses":{"approval-sub_a":{"approved":true,"requestId":"`+reqA.RequestID+`"}}}`))
	if ack.Error != nil {
		t.Fatalf("tasks/update: %+v", ack.Error)
	}
	resume := ts.call(t, mcp.MethodCampaignResume, json.RawMessage(`{"workflow_id":"pgrp-cancel"}`))
	if resume.Error != nil {
		t.Fatalf("campaign/resume after cancel: %+v", resume.Error)
	}
	ts.pollTaskStatus(t, "pgrp-cancel", mcp.TaskStatusCompleted)
	if runs := ts.dangerous.runs(); runs != 1 {
		t.Fatalf("approved sub-step must execute exactly once, ran %d times", runs)
	}
	// sub_safe must not re-execute; after must run: 1 + 1.
	if runs := ts.safe.runs(); runs != 2 {
		t.Fatalf("plain sub-step must not re-execute after cancel+resume, safe ran %d times", runs)
	}
}

// TestMRTRParallelGroupStaleAndUnknownKeys: tasks/update with unknown or
// stale keys is acked; resuming without decisions re-pauses the task with
// fresh request ids (fail closed) while completed sub-steps are not
// re-executed.
func TestMRTRParallelGroupStaleAndUnknownKeys(t *testing.T) {
	ts := newTaskTestServer(t)

	ts.callWithTasks(t, mcp.MethodCampaignStart, json.RawMessage(
		`{"id":"pgrp-stale","steps":[{"id":"grp","parallel":[`+
			`{"id":"sub_safe","tool":"safe_tool"},`+
			`{"id":"sub_a","tool":"dangerous_tool"}]}]}`))

	requests := groupPauseRequests(t, ts, "pgrp-stale")
	reqA := requests[mcp.GroupApprovalInputKey("sub_a")]

	// Unknown key and a stale request id: both acked and ignored.
	for _, payload := range []string{
		`{"taskId":"pgrp-stale","inputResponses":{"unrelated":{"approved":true}}}`,
		`{"taskId":"pgrp-stale","inputResponses":{"approval-sub_a":{"approved":true,"requestId":"req_old"}}}`,
	} {
		ack := ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(payload))
		if ack.Error != nil {
			t.Fatalf("tasks/update must ack unknown/stale keys: %+v", ack.Error)
		}
	}

	// Resume without a decision: the gate re-trips with a fresh id. The
	// resume must re-declare the tasks capability for the re-run to
	// elicit again (an approved re-run would re-establish the marker on
	// its own; an unanswered one cannot).
	resume := ts.callWithTasks(t, mcp.MethodCampaignResume, json.RawMessage(`{"workflow_id":"pgrp-stale"}`))
	if resume.Error != nil {
		t.Fatalf("campaign/resume: %+v", resume.Error)
	}
	requests2 := groupPauseRequests(t, ts, "pgrp-stale")
	reqA2 := requests2[mcp.GroupApprovalInputKey("sub_a")]
	if reqA2.RequestID == reqA.RequestID {
		t.Fatalf("re-tripped gate must mint a fresh request id, got %q twice", reqA.RequestID)
	}
	if runs := ts.safe.runs(); runs != 1 {
		t.Fatalf("completed sub-step must not re-execute, ran %d times", runs)
	}

	// Approve the fresh gate and finish.
	ack := ts.call(t, mcp.MethodTasksUpdate, json.RawMessage(
		`{"taskId":"pgrp-stale","inputResponses":{"approval-sub_a":{"approved":true,"requestId":"`+reqA2.RequestID+`"}}}`))
	if ack.Error != nil {
		t.Fatalf("tasks/update: %+v", ack.Error)
	}
	ts.call(t, mcp.MethodCampaignResume, json.RawMessage(`{"workflow_id":"pgrp-stale"}`))
	ts.pollTaskStatus(t, "pgrp-stale", mcp.TaskStatusCompleted)
	if runs := ts.dangerous.runs(); runs != 1 {
		t.Fatalf("approved sub-step must execute exactly once, ran %d times", runs)
	}
	if runs := ts.safe.runs(); runs != 1 {
		t.Fatalf("completed sub-step must not re-execute on final resume, ran %d times", runs)
	}
}

// TestCampaignRunSyncParallelApprovalFailsClosed: without the tasks
// capability, an approval-gated sub-step keeps today's fail-closed
// behavior — the sub-step fails and the group's on_fail decides.
func TestCampaignRunSyncParallelApprovalFailsClosed(t *testing.T) {
	ts := newTaskTestServer(t)
	resp := ts.call(t, mcp.MethodCampaignRun, json.RawMessage(
		`{"id":"pgrp-sync","steps":[{"id":"grp","parallel":[`+
			`{"id":"sub_safe","tool":"safe_tool"},`+
			`{"id":"sub_a","tool":"dangerous_tool"}]}]}`))
	if resp.Error != nil {
		t.Fatalf("campaign/run: %+v", resp.Error)
	}
	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(mustJSON(t, resp.Result), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" {
		t.Fatalf("capability-less campaign over a gated parallel group = %q, want failed", result.Status)
	}
	if runs := ts.dangerous.runs(); runs != 0 {
		t.Fatal("gated sub-step must not execute without capability")
	}
}
