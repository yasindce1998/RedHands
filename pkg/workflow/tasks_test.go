package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// gatedExecutor simulates the server middleware chain for MRTR tests: the
// named tool trips the approval gate (input_required) unless the call's
// context carries an affirmative approval response, mirroring what the
// approval middleware + engine adapter do in the wired server.
type gatedExecutor struct {
	mu        sync.Mutex
	gated     string
	calls     int
	bypassed  bool
	plainDone map[string]bool
}

func newGatedExecutor(gated string) *gatedExecutor {
	return &gatedExecutor{gated: gated, plainDone: map[string]bool{}}
}

func (g *gatedExecutor) exec(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
	if tool == g.gated {
		g.mu.Lock()
		g.calls++
		g.mu.Unlock()
		responses := mcp.InputResponsesFromContext(ctx)
		if responses == nil || !mcp.IsAffirmativeApproval(responses[mcp.ApprovalInputKey]) {
			return "", false, &ApprovalRequiredError{
				Tool:      tool,
				RequestID: "req_gate_1",
				Message:   fmt.Sprintf("Tool %q requires operator approval.", tool),
			}
		}
		g.mu.Lock()
		g.bypassed = true
		g.mu.Unlock()
		return "approved and executed", true, nil
	}
	g.mu.Lock()
	g.plainDone[tool] = true
	g.mu.Unlock()
	return "ok:" + tool, true, nil
}

func TestStartAsyncSavesInitialStateBeforeReturn(t *testing.T) {
	block := make(chan struct{})
	release := make(chan struct{})
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		<-block // hold the campaign in "running"
		select {
		case <-release:
			return "ok", true, nil
		case <-ctx.Done():
			return "", false, ctx.Err()
		}
	}
	engine, dir := newTestEngine(t, exec)
	stateDir := filepath.Join(dir, "state")

	taskID, already, err := engine.StartAsync(context.Background(), &EnhancedWorkflowRequest{
		ID:    "async-durable",
		Steps: []EnhancedStep{{ID: "a", Tool: "tool_a"}},
	})
	if err != nil || already {
		t.Fatalf("StartAsync: err=%v already=%v", err, already)
	}
	close(block)

	// The durable record must exist the moment StartAsync returns, before
	// any step finishes: a task id handed to a client always addresses an
	// existing checkpoint.
	state, err := engine.Status(taskID)
	if err != nil {
		t.Fatalf("state must be readable immediately after StartAsync: %v", err)
	}
	if state.Status != "running" && state.Status != "completed" {
		t.Fatalf("state after StartAsync = %q, want running or completed", state.Status)
	}
	if _, err := readStateFile(stateDir, taskID); err != nil {
		t.Fatalf("state file must exist on disk before steps complete: %v", err)
	}
	close(release)
	waitForStatus(t, engine, taskID, "completed")
}

func TestStartAsyncIdempotentRestart(t *testing.T) {
	block := make(chan struct{})
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		<-block
		return "ok", true, nil
	}
	engine, _ := newTestEngine(t, exec)
	req := &EnhancedWorkflowRequest{
		ID:    "async-idem",
		Steps: []EnhancedStep{{ID: "a", Tool: "tool_a"}},
	}

	first, already, err := engine.StartAsync(context.Background(), req)
	if err != nil || already {
		t.Fatalf("first StartAsync: err=%v already=%v", err, already)
	}
	// A duplicate start while the campaign is in flight addresses the live
	// task instead of erroring.
	second, already, err := engine.StartAsync(context.Background(), req)
	if err != nil {
		t.Fatalf("second StartAsync must not error: %v", err)
	}
	if !already {
		t.Fatal("second StartAsync must report alreadyRunning")
	}
	if second != first {
		t.Fatalf("second StartAsync id = %q, want the live task %q", second, first)
	}
	close(block)
	waitForStatus(t, engine, first, "completed")
}

func TestStartAsyncPersistsFinalResult(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return "ok:" + tool, true, nil
	}
	steps := []EnhancedStep{
		{ID: "a", Tool: "tool_a"},
		{ID: "b", Tool: "tool_b"},
	}
	engine, _ := newTestEngine(t, exec)

	taskID, _, err := engine.StartAsync(context.Background(), &EnhancedWorkflowRequest{ID: "async-final", Steps: steps})
	if err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, engine, taskID, "completed")

	state, err := engine.Status(taskID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.FinalResult) == 0 {
		t.Fatal("completed campaign must persist FinalResult")
	}
	var final WorkflowResult
	if err := json.Unmarshal(state.FinalResult, &final); err != nil {
		t.Fatalf("FinalResult malformed: %v", err)
	}
	if final.Status != "completed" || !final.Success || len(final.Steps) != 2 {
		t.Fatalf("FinalResult = %+v", final)
	}
}

// TestAsyncResultEqualsSyncRun verifies the tasks/get payload for a
// completed task is the exact campaign/run output for the same playbook.
func TestAsyncResultEqualsSyncRun(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return "ok:" + tool, true, nil
	}
	steps := []EnhancedStep{
		{ID: "a", Tool: "tool_a"},
		{ID: "b", Tool: "tool_b"},
	}
	syncEngine, _ := newTestEngine(t, exec)
	syncResult, err := syncEngine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{ID: "cmp_sync", Steps: steps})
	if err != nil {
		t.Fatal(err)
	}
	syncJSON, _ := json.Marshal(syncResult)

	asyncEngine, _ := newTestEngine(t, exec)
	taskID, _, err := asyncEngine.StartAsync(context.Background(), &EnhancedWorkflowRequest{ID: "cmp_async", Steps: steps})
	if err != nil {
		t.Fatal(err)
	}
	waitForStatus(t, asyncEngine, taskID, "completed")
	state, err := asyncEngine.Status(taskID)
	if err != nil {
		t.Fatal(err)
	}

	// The only legitimate difference is the workflow id; normalize it and
	// the state file's indentation (the checkpoint store pretty-prints,
	// campaign/run compacts).
	var compact bytes.Buffer
	if err := json.Compact(&compact, state.FinalResult); err != nil {
		t.Fatalf("FinalResult not valid JSON: %v", err)
	}
	normalized := strings.Replace(compact.String(), `"cmp_async"`, `"cmp_sync"`, 1)
	if normalized != string(syncJSON) {
		t.Fatalf("async FinalResult != sync campaign/run output:\n async: %s\n sync:  %s", normalized, syncJSON)
	}
}

func TestApprovalPauseAndResumeApproved(t *testing.T) {
	gated := newGatedExecutor("dangerous_tool")
	engine, _ := newTestEngine(t, gated.exec)

	// A task-tracked campaign pauses when a step trips the approval gate.
	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID:    "mrtr-approve",
		Steps: []EnhancedStep{{ID: "gate", Tool: "dangerous_tool"}, {ID: "after", Tool: "tool_after"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "paused" {
		t.Fatalf("campaign status = %q, want paused", result.Status)
	}
	state, err := engine.Status("mrtr-approve")
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingApproval == nil {
		t.Fatal("paused campaign must record PendingApproval")
	}
	if state.PendingApproval.Tool != "dangerous_tool" || state.PendingApproval.StepID != "gate" {
		t.Fatalf("PendingApproval = %+v", state.PendingApproval)
	}
	if state.PendingApproval.RequestID != "req_gate_1" {
		t.Fatalf("PendingApproval must carry the elicitation request id, got %q", state.PendingApproval.RequestID)
	}
	if state.NextIndex != 0 {
		t.Fatalf("gated step must re-run on resume, NextIndex = %d", state.NextIndex)
	}

	// tasks/update with an affirmative approval.
	ack, err := engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"mrtr-approve","inputResponses":{"approval":{"approved":true,"requestId":"req_gate_1"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(ack) != `{"accepted":true}` {
		t.Fatalf("tasks/update ack = %s", ack)
	}

	// Resume: the gated step re-runs with a one-call bypass and the
	// campaign completes.
	resumed, err := engine.Resume(context.Background(), "mrtr-approve")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "completed" || !resumed.Success {
		t.Fatalf("resumed campaign = %+v", resumed)
	}
	if !gated.bypassed {
		t.Fatal("approved step must execute through the approval bypass")
	}
	gated.mu.Lock()
	calls := gated.calls
	gated.mu.Unlock()
	if calls != 2 {
		t.Fatalf("gated tool called %d times, want 2 (gate + approved re-run)", calls)
	}
	final, err := engine.Status("mrtr-approve")
	if err != nil {
		t.Fatal(err)
	}
	if final.PendingApproval != nil {
		t.Fatal("resolved approval must be consumed on resume")
	}
}

func TestApprovalDeniedFailsStep(t *testing.T) {
	gated := newGatedExecutor("dangerous_tool")
	engine, _ := newTestEngine(t, gated.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID:    "mrtr-deny",
		Steps: []EnhancedStep{{ID: "gate", Tool: "dangerous_tool"}, {ID: "after", Tool: "tool_after"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// A response that is present but not affirmative is a denial.
	if _, err := engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"mrtr-deny","inputResponses":{"approval":{"approved":false}}}`)); err != nil {
		t.Fatal(err)
	}

	resumed, err := engine.Resume(context.Background(), "mrtr-deny")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "failed" {
		t.Fatalf("denied campaign status = %q, want failed (default on_fail stop)", resumed.Status)
	}
	state, _ := engine.Status("mrtr-deny")
	if state.Results["gate"].Success || state.Results["gate"].Text != "approval denied" {
		t.Fatalf("denied step result = %+v", state.Results["gate"])
	}
	if _, ok := state.Results["after"]; ok {
		t.Fatal("steps after a denied on_fail:stop step must not run")
	}
	if gated.bypassed {
		t.Fatal("denied step must never execute")
	}
}

func TestApprovalDeniedHonorsOnFailContinue(t *testing.T) {
	gated := newGatedExecutor("dangerous_tool")
	engine, _ := newTestEngine(t, gated.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "mrtr-deny-cont",
		Steps: []EnhancedStep{
			{ID: "gate", Tool: "dangerous_tool", OnFail: "continue"},
			{ID: "after", Tool: "tool_after"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"mrtr-deny-cont","inputResponses":{"approval":{"approved":false}}}`)); err != nil {
		t.Fatal(err)
	}
	resumed, err := engine.Resume(context.Background(), "mrtr-deny-cont")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "completed" {
		t.Fatalf("on_fail:continue campaign after denial = %q, want completed", resumed.Status)
	}
	state, _ := engine.Status("mrtr-deny-cont")
	if !state.Results["after"].Success {
		t.Fatal("step after a denied on_fail:continue step must run")
	}
}

func TestTaskUpdateStaleAndUnknownKeysIgnored(t *testing.T) {
	gated := newGatedExecutor("dangerous_tool")
	engine, _ := newTestEngine(t, gated.exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID:    "mrtr-stale",
		Steps: []EnhancedStep{{ID: "gate", Tool: "dangerous_tool"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Unknown key: ack and ignore.
	ack, err := engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"mrtr-stale","inputResponses":{"something_else":{"approved":true}}}`))
	if err != nil || string(ack) != `{"accepted":true}` {
		t.Fatalf("unknown key: ack=%s err=%v", ack, err)
	}
	// Stale request id: ack and ignore.
	ack, err = engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"mrtr-stale","inputResponses":{"approval":{"approved":true,"requestId":"req_old"}}}`))
	if err != nil || string(ack) != `{"accepted":true}` {
		t.Fatalf("stale id: ack=%s err=%v", ack, err)
	}
	state, _ := engine.Status("mrtr-stale")
	if state.PendingApproval == nil || state.PendingApproval.Resolved != "" {
		t.Fatalf("stale/unknown updates must not resolve the gate: %+v", state.PendingApproval)
	}
	// Unknown task: error.
	if _, err := engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"nope","inputResponses":{"approval":{"approved":true}}}`)); err == nil {
		t.Fatal("unknown taskId must error")
	}

	// The gate is still live: resume without a decision re-trips it.
	resumed, err := engine.Resume(context.Background(), "mrtr-stale")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != "paused" {
		t.Fatalf("resume without decision = %q, want paused again", resumed.Status)
	}
	state, _ = engine.Status("mrtr-stale")
	if state.PendingApproval == nil {
		t.Fatal("re-tripped gate must record a fresh PendingApproval")
	}
}

func TestApprovalErrorWithoutGateSupportFailsStep(t *testing.T) {
	// A campaign whose executor reports an approval-required error but
	// whose gate is never answered behaves like any paused campaign: the
	// step re-trips. What must never happen is the step silently
	// executing.
	gated := newGatedExecutor("dangerous_tool")
	engine, _ := newTestEngine(t, gated.exec)
	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID:    "mrtr-unanswered",
		Steps: []EnhancedStep{{ID: "gate", Tool: "dangerous_tool"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gated.bypassed {
		t.Fatal("gated tool must not execute without approval")
	}
	if _, err := engine.TaskUpdateFromJSON(json.RawMessage(
		`{"taskId":"mrtr-unanswered","inputResponses":{"approval":{"approved":true}}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Resume(context.Background(), "mrtr-unanswered"); err != nil {
		t.Fatal(err)
	}
	if !gated.bypassed {
		t.Fatal("approved resume must execute the gated step")
	}
}

func TestApprovalRequiredErrorIs(t *testing.T) {
	wrapped := fmt.Errorf("step failed: %w", &ApprovalRequiredError{Tool: "x"})
	if !errors.Is(wrapped, ErrApprovalRequired) {
		t.Fatal("ApprovalRequiredError must match ErrApprovalRequired through wrapping")
	}
	var target *ApprovalRequiredError
	if !errors.As(wrapped, &target) || target.Tool != "x" {
		t.Fatal("ApprovalRequiredError must unwrap to itself")
	}
}

func TestPendingApprovalDecision(t *testing.T) {
	cases := []struct {
		name             string
		response         string
		approvedResponse bool
	}{
		{"approved", `{"approved":true}`, true},
		{"denied", `{"approved":false}`, false},
		{"not an object", `"yes"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pa := &PendingApproval{Response: json.RawMessage(tc.response)}
			approved, responded := pa.Decision()
			if !responded || approved != tc.approvedResponse {
				t.Fatalf("Decision() = (%v, %v)", approved, responded)
			}
		})
	}
	// Unanswered gate.
	pa := &PendingApproval{}
	if _, responded := pa.Decision(); responded {
		t.Fatal("unanswered gate must not report a decision")
	}
}

// readStateFile checks the checkpoint file exists on disk.
func readStateFile(stateDir, workflowID string) ([]byte, error) {
	return os.ReadFile(filepath.Join(stateDir, workflowID+".json"))
}

// waitForStatus polls the persisted state until it reaches want (or the
// test times out).
func waitForStatus(t *testing.T, engine *EnhancedEngine, workflowID, want string) *State {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		state, err := engine.Status(workflowID)
		if err == nil && state.Status == want {
			return state
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("workflow %s: %v", workflowID, err)
			}
			t.Fatalf("workflow %s stuck in %q, want %q", workflowID, state.Status, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
