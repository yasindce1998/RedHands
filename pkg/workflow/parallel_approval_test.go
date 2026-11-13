package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// groupGatedExecutor simulates the server middleware chain for MRTR
// parallel-group tests: the named tools trip the approval gate
// (input_required) unless the call's context carries an affirmative
// approval response, mirroring what the approval middleware + engine
// adapter do in the wired server. Each gate mints a FRESH request id so
// re-tripped gates are distinguishable from the ones that paused the
// campaign. Tools listed in fail fail for non-approval reasons.
type groupGatedExecutor struct {
	mu    sync.Mutex
	gated map[string]bool
	fail  map[string]bool
	calls map[string]int
	seq   int
}

func newGroupGatedExecutor(gated ...string) *groupGatedExecutor {
	g := &groupGatedExecutor{
		gated: map[string]bool{},
		fail:  map[string]bool{},
		calls: map[string]int{},
	}
	for _, name := range gated {
		g.gated[name] = true
	}
	return g
}

func (g *groupGatedExecutor) failing(tools ...string) *groupGatedExecutor {
	for _, name := range tools {
		g.fail[name] = true
	}
	return g
}

func (g *groupGatedExecutor) exec(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
	g.mu.Lock()
	g.calls[tool]++
	seq := g.seq + 1
	g.seq = seq
	g.mu.Unlock()
	if g.gated[tool] {
		responses := mcp.InputResponsesFromContext(ctx)
		if responses == nil || !mcp.IsAffirmativeApproval(responses[mcp.ApprovalInputKey]) {
			return "", false, &ApprovalRequiredError{
				Tool:      tool,
				RequestID: fmt.Sprintf("req_%s_%d", tool, seq),
				Message:   fmt.Sprintf("Tool %q requires operator approval.", tool),
			}
		}
		return "approved:" + tool, true, nil
	}
	if g.fail[tool] {
		return "tool failed", false, nil
	}
	return "ok:" + tool, true, nil
}

func (g *groupGatedExecutor) callCount(tool string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[tool]
}

// groupApprovalUpdate builds a tasks/update payload answering the given
// sub-step gates.
func groupApprovalUpdate(taskID string, answers map[string]string) json.RawMessage {
	responses := map[string]json.RawMessage{}
	for subID, decision := range answers {
		responses[mcp.GroupApprovalInputKey(subID)] = json.RawMessage(decision)
	}
	data, _ := json.Marshal(map[string]any{
		"taskId":         taskID,
		"inputResponses": responses,
	})
	return data
}

func approveUpdate(taskID, subID, requestID string) json.RawMessage {
	return groupApprovalUpdate(taskID, map[string]string{
		subID: fmt.Sprintf(`{"approved":true,"requestId":%q}`, requestID),
	})
}

func denyUpdate(taskID, subID string) json.RawMessage {
	return groupApprovalUpdate(taskID, map[string]string{
		subID: `{"approved":false}`,
	})
}

// TestParallelGroupMultiGatePauseAndPartialReplay: a 3-sub-step group with
// 2 gated sub-steps pauses ONCE with two pending requests; the completed
// sub-step is not re-executed on resume, and each approved sub-step
// executes exactly once more.
func TestParallelGroupMultiGatePauseAndPartialReplay(t *testing.T) {
	exec := newGroupGatedExecutor("gated_one", "gated_two")
	engine, _ := newTestEngine(t, exec.exec)

	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "pgrp-replay",
		Steps: []EnhancedStep{
			{ID: "grp", Parallel: []EnhancedStep{
				{ID: "plain", Tool: "plain_tool"},
				{ID: "g1", Tool: "gated_one"},
				{ID: "g2", Tool: "gated_two"},
			}},
			{ID: "after", Tool: "after_tool"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "paused" {
		t.Fatalf("campaign status = %q, want paused", result.Status)
	}

	state, err := engine.Status("pgrp-replay")
	if err != nil {
		t.Fatal(err)
	}
	pa := state.PendingApproval
	if pa == nil || !pa.Group {
		t.Fatalf("paused group must record a group PendingApproval: %+v", pa)
	}
	if pa.StepID != "grp" {
		t.Fatalf("group PendingApproval.StepID = %q, want grp", pa.StepID)
	}
	if len(pa.Requests) != 2 {
		t.Fatalf("group pause must carry one request per gated sub-step, got %d", len(pa.Requests))
	}
	bySub := map[string]*PendingApprovalRequest{}
	for _, r := range pa.Requests {
		bySub[r.StepID] = r
	}
	req1, req2 := bySub["g1"], bySub["g2"]
	if req1 == nil || req2 == nil {
		t.Fatalf("gated requests = %+v", pa.Requests)
	}
	if req1.Tool != "gated_one" || req2.Tool != "gated_two" {
		t.Fatalf("gated request tools = %+v", pa.Requests)
	}
	if req1.RequestID == "" || req1.RequestID == req2.RequestID {
		t.Fatalf("gated sub-steps must carry distinct request ids: %+v", pa.Requests)
	}
	if !state.GroupCompleted["plain"] {
		t.Fatalf("completed sub-step must be recorded in GroupCompleted: %v", state.GroupCompleted)
	}
	if !state.Results["plain"].Success {
		t.Fatalf("completed sub-step result must be checkpointed: %+v", state.Results["plain"])
	}
	if _, ok := state.Results["g1"]; ok {
		t.Fatal("gated sub-step must not have a recorded result while paused")
	}
	if state.NextIndex != 0 {
		t.Fatalf("paused group must re-run on resume, NextIndex = %d", state.NextIndex)
	}
	if c := exec.callCount("plain_tool"); c != 1 {
		t.Fatalf("plain sub-step called %d times, want 1", c)
	}
	if c := exec.callCount("gated_one"); c != 1 {
		t.Fatalf("gated sub-step tripped %d times, want 1", c)
	}
	if c := exec.callCount("after_tool"); c != 0 {
		t.Fatalf("step after the paused group must not run, ran %d times", c)
	}

	// Approve both gates, then resume: only the gated sub-steps re-run.
	for _, sub := range []string{"g1", "g2"} {
		ack, err := engine.TaskUpdateFromJSON(approveUpdate("pgrp-replay", sub, bySub[sub].RequestID))
		if err != nil || string(ack) != `{"accepted":true}` {
			t.Fatalf("tasks/update approve %s: ack=%s err=%v", sub, ack, err)
		}
	}

	resumed, err := engine.Resume(context.Background(), "pgrp-replay")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "completed" || !resumed.Success {
		t.Fatalf("resumed campaign = %+v", resumed)
	}
	if c := exec.callCount("plain_tool"); c != 1 {
		t.Fatalf("completed sub-step must NOT re-execute on resume, called %d times", c)
	}
	if c := exec.callCount("gated_one"); c != 2 {
		t.Fatalf("approved sub-step must execute exactly once more, called %d times", c)
	}
	if c := exec.callCount("gated_two"); c != 2 {
		t.Fatalf("approved sub-step must execute exactly once more, called %d times", c)
	}
	if c := exec.callCount("after_tool"); c != 1 {
		t.Fatalf("step after the group must run once, ran %d times", c)
	}

	final, err := engine.Status("pgrp-replay")
	if err != nil {
		t.Fatal(err)
	}
	if final.PendingApproval != nil {
		t.Fatal("resolved group approval must be consumed on resume")
	}
	if final.GroupCompleted != nil {
		t.Fatalf("completion set must be cleared when the group completes: %v", final.GroupCompleted)
	}
	if !final.Results["g1"].Success || !final.Results["g2"].Success {
		t.Fatalf("approved sub-steps must record successes: g1=%+v g2=%+v", final.Results["g1"], final.Results["g2"])
	}
}

// TestParallelGroupApproveSomeDenySomeContinue: a mixed round — one gate
// approved, one denied — completes under on_fail:continue with the denied
// sub-step recorded as failed ("approval denied") and never executed.
func TestParallelGroupApproveSomeDenySomeContinue(t *testing.T) {
	exec := newGroupGatedExecutor("gated_one", "gated_two")
	engine, _ := newTestEngine(t, exec.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "pgrp-mixed",
		Steps: []EnhancedStep{
			{ID: "grp", OnFail: "continue", Parallel: []EnhancedStep{
				{ID: "plain", Tool: "plain_tool"},
				{ID: "g1", Tool: "gated_one"},
				{ID: "g2", Tool: "gated_two"},
			}},
			{ID: "after", Tool: "after_tool"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	state, _ := engine.Status("pgrp-mixed")
	bySub := map[string]*PendingApprovalRequest{}
	for _, r := range state.PendingApproval.Requests {
		bySub[r.StepID] = r
	}
	if _, err := engine.TaskUpdateFromJSON(approveUpdate("pgrp-mixed", "g1", bySub["g1"].RequestID)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.TaskUpdateFromJSON(denyUpdate("pgrp-mixed", "g2")); err != nil {
		t.Fatal(err)
	}

	resumed, err := engine.Resume(context.Background(), "pgrp-mixed")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "completed" || !resumed.Success {
		t.Fatalf("on_fail:continue group with a denied sub-step = %+v", resumed)
	}
	if c := exec.callCount("gated_one"); c != 2 {
		t.Fatalf("approved sub-step must execute exactly once more, called %d times", c)
	}
	if c := exec.callCount("gated_two"); c != 1 {
		t.Fatalf("denied sub-step must never execute (only the gate trip), called %d times", c)
	}
	if c := exec.callCount("plain_tool"); c != 1 {
		t.Fatalf("completed sub-step must not re-execute, called %d times", c)
	}
	final, _ := engine.Status("pgrp-mixed")
	if final.Results["g2"].Success || final.Results["g2"].Text != "approval denied" {
		t.Fatalf("denied sub-step result = %+v", final.Results["g2"])
	}
	if !final.Results["g1"].Success {
		t.Fatalf("approved sub-step result = %+v", final.Results["g1"])
	}
	if !final.Results["after"].Success {
		t.Fatal("step after an on_fail:continue group must run")
	}
}

// TestParallelGroupDenyStopsCampaign: with the default on_fail (stop), a
// denied sub-step fails the whole campaign.
func TestParallelGroupDenyStopsCampaign(t *testing.T) {
	exec := newGroupGatedExecutor("gated_one")
	engine, _ := newTestEngine(t, exec.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "pgrp-deny-stop",
		Steps: []EnhancedStep{
			{ID: "grp", Parallel: []EnhancedStep{
				{ID: "g1", Tool: "gated_one"},
			}},
			{ID: "after", Tool: "after_tool"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.TaskUpdateFromJSON(denyUpdate("pgrp-deny-stop", "g1")); err != nil {
		t.Fatal(err)
	}
	resumed, err := engine.Resume(context.Background(), "pgrp-deny-stop")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "failed" {
		t.Fatalf("denied sub-step with default on_fail = %q, want failed", resumed.Status)
	}
	if c := exec.callCount("gated_one"); c != 1 {
		t.Fatalf("denied sub-step must never execute, called %d times", c)
	}
	if c := exec.callCount("after_tool"); c != 0 {
		t.Fatal("steps after a stopped group must not run")
	}
}

// TestParallelGroupKeepsNonApprovalFailuresOnReplay: a sub-step that
// failed for non-approval reasons during the paused partial run keeps its
// recorded failure and is not re-executed on resume.
func TestParallelGroupKeepsNonApprovalFailuresOnReplay(t *testing.T) {
	exec := newGroupGatedExecutor("gated_one").failing("broken_tool")
	engine, _ := newTestEngine(t, exec.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "pgrp-keepfail",
		Steps: []EnhancedStep{
			{ID: "grp", OnFail: "continue", Parallel: []EnhancedStep{
				{ID: "plain", Tool: "plain_tool"},
				{ID: "broken", Tool: "broken_tool"},
				{ID: "g1", Tool: "gated_one"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	state, _ := engine.Status("pgrp-keepfail")
	if len(state.PendingApproval.Requests) != 1 || state.PendingApproval.Requests[0].StepID != "g1" {
		t.Fatalf("gated requests = %+v", state.PendingApproval.Requests)
	}
	if state.Results["broken"].Success {
		t.Fatalf("non-approval failure must be checkpointed: %+v", state.Results["broken"])
	}
	if _, ok := state.GroupCompleted["broken"]; ok {
		t.Fatal("a failed sub-step must not enter the completion set")
	}

	if _, err := engine.TaskUpdateFromJSON(approveUpdate("pgrp-keepfail", "g1", state.PendingApproval.Requests[0].RequestID)); err != nil {
		t.Fatal(err)
	}
	resumed, err := engine.Resume(context.Background(), "pgrp-keepfail")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "completed" {
		t.Fatalf("on_fail:continue group = %+v", resumed)
	}
	if c := exec.callCount("broken_tool"); c != 1 {
		t.Fatalf("non-approval failure must not re-execute on resume, called %d times", c)
	}
	if c := exec.callCount("plain_tool"); c != 1 {
		t.Fatalf("completed sub-step must not re-execute, called %d times", c)
	}
	if c := exec.callCount("gated_one"); c != 2 {
		t.Fatalf("approved sub-step must execute once more, called %d times", c)
	}
	final, _ := engine.Status("pgrp-keepfail")
	if final.Results["broken"].Success || final.Results["broken"].Text != "tool failed" {
		t.Fatalf("replayed failure must keep its recorded result: %+v", final.Results["broken"])
	}
}

// TestParallelGroupCancelWhilePaused: cancelling a campaign paused inside
// a group marks it cancelled; resuming after cancel continues from the
// group's checkpoint exactly like the sequential approval pause does.
func TestParallelGroupCancelWhilePaused(t *testing.T) {
	exec := newGroupGatedExecutor("gated_one")
	engine, _ := newTestEngine(t, exec.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "pgrp-cancel",
		Steps: []EnhancedStep{
			{ID: "grp", Parallel: []EnhancedStep{
				{ID: "plain", Tool: "plain_tool"},
				{ID: "g1", Tool: "gated_one"},
			}},
			{ID: "after", Tool: "after_tool"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := engine.Cancel("pgrp-cancel"); err != nil {
		t.Fatalf("cancel while paused-in-group: %v", err)
	}
	state, _ := engine.Status("pgrp-cancel")
	if state.Status != "cancelled" {
		t.Fatalf("status after cancel = %q, want cancelled", state.Status)
	}
	// The pause record survives the cancel marker so a later resume can
	// still answer the gates.
	if state.PendingApproval == nil || !state.PendingApproval.Group {
		t.Fatalf("cancel must preserve the group pause record: %+v", state.PendingApproval)
	}

	// Resume after cancel: answer the gate and finish.
	reqID := state.PendingApproval.Requests[0].RequestID
	if _, err := engine.TaskUpdateFromJSON(approveUpdate("pgrp-cancel", "g1", reqID)); err != nil {
		t.Fatal(err)
	}
	resumed, err := engine.Resume(context.Background(), "pgrp-cancel")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "completed" || !resumed.Success {
		t.Fatalf("resumed-after-cancel campaign = %+v", resumed)
	}
	if c := exec.callCount("plain_tool"); c != 1 {
		t.Fatalf("completed sub-step must not re-execute after cancel+resume, called %d times", c)
	}
	if c := exec.callCount("gated_one"); c != 2 {
		t.Fatalf("approved sub-step must execute once more, called %d times", c)
	}
}

// TestParallelGroupGotoResetsCompletion: when a paused group re-runs via
// on_fail goto (a fresh execution, not a resume), the run-scoped
// completion set resets and every sub-step re-executes.
func TestParallelGroupGotoResetsCompletion(t *testing.T) {
	exec := newGroupGatedExecutor("gated_one")
	engine, _ := newTestEngine(t, exec.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "pgrp-goto",
		Steps: []EnhancedStep{
			{ID: "grp", OnFail: "goto:grp", Parallel: []EnhancedStep{
				{ID: "plain", Tool: "plain_tool"},
				{ID: "g1", Tool: "gated_one"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	state, _ := engine.Status("pgrp-goto")
	if !state.GroupCompleted["plain"] {
		t.Fatalf("completion set before goto = %v", state.GroupCompleted)
	}
	firstReqID := state.PendingApproval.Requests[0].RequestID

	// Deny the gate: the sub-step fails, the group's on_fail jumps back
	// to the group, and the goto re-run is a fresh execution.
	if _, err := engine.TaskUpdateFromJSON(denyUpdate("pgrp-goto", "g1")); err != nil {
		t.Fatal(err)
	}
	resumed, err := engine.Resume(context.Background(), "pgrp-goto")
	if err != nil {
		t.Fatal(err)
	}
	// The wholesale re-run trips the gate again, so the campaign pauses
	// inside the group a second time.
	if resumed.Status != "paused" {
		t.Fatalf("campaign after goto re-run = %q, want paused (gate re-tripped)", resumed.Status)
	}
	if c := exec.callCount("plain_tool"); c != 2 {
		t.Fatalf("goto re-run must re-execute completed sub-steps (completion set reset), called %d times", c)
	}
	if c := exec.callCount("gated_one"); c != 2 {
		t.Fatalf("goto re-run must re-execute the gated sub-step, called %d times", c)
	}

	state, _ = engine.Status("pgrp-goto")
	if state.PendingApproval == nil || len(state.PendingApproval.Requests) != 1 {
		t.Fatalf("re-tripped gate must record a fresh pause: %+v", state.PendingApproval)
	}
	secondReqID := state.PendingApproval.Requests[0].RequestID
	if secondReqID == firstReqID {
		t.Fatalf("re-tripped gate must mint a fresh request id, got %q twice", firstReqID)
	}
	if !state.GroupCompleted["plain"] {
		t.Fatalf("goto re-run must rebuild the completion set from its own successes: %v", state.GroupCompleted)
	}

	// Finishing the second pause completes the campaign.
	if _, err := engine.TaskUpdateFromJSON(approveUpdate("pgrp-goto", "g1", secondReqID)); err != nil {
		t.Fatal(err)
	}
	final, err := engine.Resume(context.Background(), "pgrp-goto")
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "completed" || !final.Success {
		t.Fatalf("campaign after second resume = %+v", final)
	}
	if c := exec.callCount("plain_tool"); c != 2 {
		t.Fatalf("completed sub-step must not re-execute within one group run, called %d times", c)
	}
	if c := exec.callCount("gated_one"); c != 3 {
		t.Fatalf("approved sub-step must execute once more, called %d times", c)
	}
}

// TestParallelGroupUnansweredGatesReTripFresh: tasks/update with unknown
// or stale keys is acked and ignored; resuming without decisions re-trips
// the gates with fresh request ids, and completed sub-steps still do not
// re-execute.
func TestParallelGroupUnansweredGatesReTripFresh(t *testing.T) {
	exec := newGroupGatedExecutor("gated_one", "gated_two")
	engine, _ := newTestEngine(t, exec.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "pgrp-stale",
		Steps: []EnhancedStep{
			{ID: "grp", Parallel: []EnhancedStep{
				{ID: "plain", Tool: "plain_tool"},
				{ID: "g1", Tool: "gated_one"},
				{ID: "g2", Tool: "gated_two"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	state, _ := engine.Status("pgrp-stale")
	firstIDs := map[string]string{}
	for _, r := range state.PendingApproval.Requests {
		firstIDs[r.StepID] = r.RequestID
	}

	// Unknown key: ack and ignore.
	ack, err := engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"pgrp-stale","inputResponses":{"something_else":{"approved":true}}}`))
	if err != nil || string(ack) != `{"accepted":true}` {
		t.Fatalf("unknown key: ack=%s err=%v", ack, err)
	}
	// The plain sequential key is unknown for a group pause: ack and
	// ignore.
	ack, err = engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"pgrp-stale","inputResponses":{"approval":{"approved":true}}}`))
	if err != nil || string(ack) != `{"accepted":true}` {
		t.Fatalf("sequential key on group pause: ack=%s err=%v", ack, err)
	}
	// Stale request id: ack and ignore.
	ack, err = engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"pgrp-stale","inputResponses":{"approval-g1":{"approved":true,"requestId":"req_old"}}}`))
	if err != nil || string(ack) != `{"accepted":true}` {
		t.Fatalf("stale id: ack=%s err=%v", ack, err)
	}
	state, _ = engine.Status("pgrp-stale")
	for _, r := range state.PendingApproval.Requests {
		if r.Resolved != "" {
			t.Fatalf("unknown/stale updates must not resolve group gates: %+v", r)
		}
	}

	// Resume without decisions: the gates re-trip with fresh ids and the
	// campaign pauses again (fail closed).
	resumed, err := engine.Resume(context.Background(), "pgrp-stale")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "paused" {
		t.Fatalf("resume without decisions = %q, want paused again", resumed.Status)
	}
	state, _ = engine.Status("pgrp-stale")
	if state.PendingApproval == nil || len(state.PendingApproval.Requests) != 2 {
		t.Fatalf("re-tripped gates must record fresh requests: %+v", state.PendingApproval)
	}
	for _, r := range state.PendingApproval.Requests {
		if r.RequestID == "" || r.RequestID == firstIDs[r.StepID] {
			t.Fatalf("re-tripped gate for %s must mint a fresh request id: %q -> %q", r.StepID, firstIDs[r.StepID], r.RequestID)
		}
	}
	if c := exec.callCount("plain_tool"); c != 1 {
		t.Fatalf("completed sub-step must not re-execute on unanswered resume, called %d times", c)
	}
	if c := exec.callCount("gated_one"); c != 2 {
		t.Fatalf("unanswered gate must re-trip, called %d times", c)
	}
}

// TestSequentialApprovalUnaffectedByGroupFields: the sequential approval
// pause keeps its single-request shape (flat fields, no Group flag), and
// a group key does not resolve it.
func TestSequentialApprovalUnaffectedByGroupFields(t *testing.T) {
	gated := newGatedExecutor("dangerous_tool")
	engine, _ := newTestEngine(t, gated.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID:    "seq-shape",
		Steps: []EnhancedStep{{ID: "gate", Tool: "dangerous_tool"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	state, _ := engine.Status("seq-shape")
	pa := state.PendingApproval
	if pa == nil || pa.Group || len(pa.Requests) != 0 {
		t.Fatalf("sequential pause must keep the flat single-gate shape: %+v", pa)
	}
	if pa.RequestID != "req_gate_1" || pa.StepID != "gate" {
		t.Fatalf("sequential pause fields = %+v", pa)
	}
	// A group-style key is unknown for a sequential pause: ack, ignore.
	ack, err := engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"seq-shape","inputResponses":{"approval-gate":{"approved":true}}}`))
	if err != nil || string(ack) != `{"accepted":true}` {
		t.Fatalf("group key on sequential pause: ack=%s err=%v", ack, err)
	}
	state, _ = engine.Status("seq-shape")
	if state.PendingApproval.Resolved != "" {
		t.Fatalf("group key must not resolve a sequential gate: %+v", state.PendingApproval)
	}
}
