package workflow

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// execCounter wraps a ToolExecutor that counts calls and returns "ok".
func execCounter() (func(context.Context, string, json.RawMessage) (string, bool, error), func() []string) {
	var mu sync.Mutex
	var calls []string
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		mu.Lock()
		calls = append(calls, tool)
		mu.Unlock()
		return "ok", true, nil
	}
	return exec, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), calls...)
	}
}

// TestCampaignCrossReplicaCancel verifies that a Cancel issued by a second
// engine (process) sharing the state directory stops the campaign executing
// in the first engine at its next checkpoint, and that the campaign can then
// be resumed to run its remaining steps.
func TestCampaignCrossReplicaCancel(t *testing.T) {
	exec, calls := execCounter()

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	engine := NewEnhancedEngine(exec, stateDir, filepath.Join(dir, "templates"), 4)

	steps := []EnhancedStep{
		{ID: "one", Tool: "one"},
		{ID: "two", Tool: "two"},
		{ID: "three", Tool: "three"},
	}

	// While step "two" executes, a second replica sharing the state dir
	// cancels the campaign.
	cancelExec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		if tool == "two" {
			other := NewEnhancedEngine(
				func(context.Context, string, json.RawMessage) (string, bool, error) { return "ok", true, nil },
				stateDir, filepath.Join(dir, "templates"), 4)
			if err := other.Cancel("cross-cancel"); err != nil {
				t.Errorf("cross-replica cancel: %v", err)
			}
		}
		return exec(ctx, tool, params)
	}
	engine.execute = cancelExec

	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID:    "cross-cancel",
		Steps: steps,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Status != "cancelled" || result.Success {
		t.Fatalf("expected cancelled result, got %+v", result)
	}
	if got := calls(); strings.Join(got, ",") != "one,two" {
		t.Fatalf("engine should stop at the checkpoint after the cancel, ran %v", got)
	}

	state, err := engine.Status("cross-cancel")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if state.Status != "cancelled" {
		t.Fatalf("persisted state should be cancelled, got %s", state.Status)
	}
	if state.NextIndex != 2 {
		t.Fatalf("checkpoint should preserve completed steps, next_index=%d", state.NextIndex)
	}

	// The cancelled campaign resumes and finishes its remaining step; the
	// stale cancelled marker must not abort the resumed run.
	resumed, err := engine.Resume(context.Background(), "cross-cancel")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !resumed.Success || resumed.Status != "completed" {
		t.Fatalf("resumed campaign should complete: %+v", resumed)
	}
	if got := calls(); strings.Join(got, ",") != "one,two,three" {
		t.Fatalf("resume should run only the remaining step, ran %v", got)
	}
}

// TestCampaignLockReleasedAfterCompletion verifies the run lock is released
// when a campaign finishes, so re-running the same workflow ID succeeds.
func TestCampaignLockReleasedAfterCompletion(t *testing.T) {
	exec, _ := execCounter()
	engine, _ := newTestEngine(t, exec)
	req := &EnhancedWorkflowRequest{
		ID:    "relock",
		Steps: []EnhancedStep{{ID: "a", Tool: "t"}},
	}

	first, err := engine.RunEnhanced(context.Background(), req)
	if err != nil || !first.Success {
		t.Fatalf("first run: result=%+v err=%v", first, err)
	}
	second, err := engine.RunEnhanced(context.Background(), req)
	if err != nil || !second.Success {
		t.Fatalf("second run after completion should succeed: result=%+v err=%v", second, err)
	}
}

// TestTemplateVarsNotMutated verifies Instantiate applies defaults to a copy
// of the caller's vars map instead of writing into it.
func TestTemplateVarsNotMutated(t *testing.T) {
	dir := t.TempDir()
	tm := NewTemplateManager(filepath.Join(dir, "templates"))
	tmpl := &Template{
		Name: "vars-test",
		Vars: []TemplateVar{
			{Name: "domain", Required: true},
			{Name: "timeout", Default: "30"},
		},
		Steps: []EnhancedStep{{
			ID:     "s",
			Tool:   "t",
			Params: json.RawMessage(`{"domain":"{{domain}}","timeout":"{{timeout}}"}`),
		}},
	}
	if err := tm.Save(tmpl); err != nil {
		t.Fatalf("save template: %v", err)
	}

	vars := map[string]string{"domain": "example.com"}
	req, err := tm.Instantiate("vars-test", vars)
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}

	if len(vars) != 1 || vars["domain"] != "example.com" {
		t.Fatalf("caller vars map was mutated: %v", vars)
	}
	if req.Vars["timeout"] != "30" || req.Vars["domain"] != "example.com" {
		t.Fatalf("defaults not applied to the copy: %v", req.Vars)
	}
	var p map[string]any
	if err := json.Unmarshal(req.Steps[0].Params, &p); err != nil {
		t.Fatalf("substituted params invalid: %v (%s)", err, req.Steps[0].Params)
	}
	if p["domain"] != "example.com" || p["timeout"] != "30" {
		t.Fatalf("template substitution wrong: %v", p)
	}
}

// TestConditionStepValidation verifies that conditions referencing unknown
// step IDs or out-of-range indices are rejected at plan-validation time,
// while declared IDs, $prev/prev, and in-range indices are accepted.
func TestConditionStepValidation(t *testing.T) {
	cases := []struct {
		name    string
		steps   []EnhancedStep
		wantErr string
	}{
		{
			name: "typoed step id",
			steps: []EnhancedStep{
				{ID: "scan", Tool: "t"},
				{ID: "act", Tool: "t", Condition: &Condition{Step: "scna", Op: "success"}},
			},
			wantErr: `unknown step "scna"`,
		},
		{
			name: "out of range index",
			steps: []EnhancedStep{
				{ID: "a", Tool: "t"},
				{ID: "b", Tool: "t", Condition: &Condition{Step: "5", Op: "success"}},
			},
			wantErr: `unknown step "5"`,
		},
		{
			name: "negative index",
			steps: []EnhancedStep{
				{ID: "a", Tool: "t"},
				{ID: "b", Tool: "t", Condition: &Condition{Step: "-1", Op: "success"}},
			},
			wantErr: `unknown step "-1"`,
		},
		{
			name: "typoed parallel sub-step id",
			steps: []EnhancedStep{
				{Parallel: []EnhancedStep{{ID: "p1", Tool: "t"}}},
				{ID: "b", Tool: "t", Condition: &Condition{Step: "p9", Op: "success"}},
			},
			wantErr: `unknown step "p9"`,
		},
		{
			name: "valid references",
			steps: []EnhancedStep{
				{ID: "a", Tool: "t"},
				{ID: "b", Tool: "t", Condition: &Condition{Step: "$prev", Op: "success"}},
				{ID: "c", Tool: "t", Condition: &Condition{Step: "prev", Op: "success"}},
				{ID: "d", Tool: "t", Condition: &Condition{Step: "0", Op: "success"}},
				{ID: "e", Tool: "t", Condition: &Condition{Step: "a", Op: "success"}},
				{ID: "f", Tool: "t", Condition: &Condition{Op: "success"}}, // empty step = $prev
				{Parallel: []EnhancedStep{{ID: "p1", Tool: "t"}, {ID: "p2", Tool: "t"}}},
				// Forward reference to a later step ID.
				{ID: "g", Tool: "t", Condition: &Condition{Step: "h", Op: "success"}},
				{ID: "h", Tool: "t", Condition: &Condition{Step: "p1", Op: "success"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSteps(tc.steps)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid plan, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected validation error %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}

	// Invalid condition references are rejected before any step executes.
	exec, calls := execCounter()
	engine, _ := newTestEngine(t, exec)
	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "bad-cond",
		Steps: []EnhancedStep{
			{ID: "scan", Tool: "t"},
			{ID: "act", Tool: "t", Condition: &Condition{Step: "nope", Op: "success"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("expected unknown-condition-step error, got %v", err)
	}
	if got := calls(); len(got) != 0 {
		t.Fatalf("invalid plan should not execute, ran %v", got)
	}
}

// TestStructuredFromText verifies the exported JSON extraction helper used
// by the engine and, later, by structured-content migration in the app layer.
func TestStructuredFromText(t *testing.T) {
	raw, ok := StructuredFromText(`  {"a":1,"b":[2,3]}  `)
	if !ok || strings.TrimSpace(string(raw)) != `{"a":1,"b":[2,3]}` {
		t.Fatalf("pure JSON extraction failed: ok=%v raw=%s", ok, raw)
	}

	raw, ok = StructuredFromText("## Findings\n```json\n{\"hosts\":[\"10.0.0.1\"]}\n```\ntrailing prose")
	if !ok || strings.TrimSpace(string(raw)) != `{"hosts":["10.0.0.1"]}` {
		t.Fatalf("fenced JSON extraction failed: ok=%v raw=%s", ok, raw)
	}

	for _, s := range []string{"", "   ", "plain text output", "```json\nnot json\n```", "```json\n{\"unclosed\":\n```"} {
		if _, ok := StructuredFromText(s); ok {
			t.Fatalf("non-JSON input %q extracted as structured", s)
		}
	}
}
