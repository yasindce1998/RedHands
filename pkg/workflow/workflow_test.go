package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// mockExecutor creates a ToolExecutor that records calls and returns predefined results.
func mockExecutor(results []struct {
	text    string
	success bool
	err     error
}) ToolExecutor {
	call := 0
	return func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		if call >= len(results) {
			return "", false, fmt.Errorf("unexpected call %d", call)
		}
		r := results[call]
		call++
		return r.text, r.success, r.err
	}
}

func TestBasicSequentialExecution(t *testing.T) {
	exec := mockExecutor([]struct {
		text    string
		success bool
		err     error
	}{
		{"scan complete", true, nil},
		{"parse done", true, nil},
		{"report generated", true, nil},
	})

	engine := NewEngine(exec)
	req := &WorkflowRequest{
		Steps: []Step{
			{Tool: "nmap_scan", Params: json.RawMessage(`{"target":"10.0.0.1"}`)},
			{Tool: "parse_output", Params: json.RawMessage(`{"format":"xml"}`)},
			{Tool: "generate_report", Params: json.RawMessage(`{"type":"html"}`)},
		},
	}

	result, err := engine.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected workflow to succeed")
	}
	if len(result.Steps) != 3 {
		t.Fatalf("expected 3 step results, got %d", len(result.Steps))
	}
	if result.Steps[0].Text != "scan complete" {
		t.Errorf("step 0 text = %q, want %q", result.Steps[0].Text, "scan complete")
	}
	if result.Steps[1].Text != "parse done" {
		t.Errorf("step 1 text = %q, want %q", result.Steps[1].Text, "parse done")
	}
	if result.Steps[2].Text != "report generated" {
		t.Errorf("step 2 text = %q, want %q", result.Steps[2].Text, "report generated")
	}
}

func TestPrevTextSubstitution(t *testing.T) {
	var capturedParams []json.RawMessage

	exec := func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		capturedParams = append(capturedParams, params)
		if toolName == "step_a" {
			return "output_from_a", true, nil
		}
		return "final", true, nil
	}

	engine := NewEngine(exec)
	req := &WorkflowRequest{
		Steps: []Step{
			{Tool: "step_a", Params: json.RawMessage(`{"target":"host"}`)},
			{Tool: "step_b", Params: json.RawMessage(`{"input":"$prev.text"}`)},
		},
	}

	result, err := engine.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}

	// Check that $prev.text was substituted in step_b's params
	var step2Params map[string]string
	if err := json.Unmarshal(capturedParams[1], &step2Params); err != nil {
		t.Fatalf("failed to unmarshal captured params: %v", err)
	}
	if step2Params["input"] != "output_from_a" {
		t.Errorf("$prev.text not substituted: got %q, want %q", step2Params["input"], "output_from_a")
	}
}

func TestStepNTextSubstitution(t *testing.T) {
	var capturedParams []json.RawMessage

	exec := func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		capturedParams = append(capturedParams, params)
		switch toolName {
		case "step_0":
			return "result_zero", true, nil
		case "step_1":
			return "result_one", true, nil
		default:
			return "done", true, nil
		}
	}

	engine := NewEngine(exec)
	req := &WorkflowRequest{
		Steps: []Step{
			{Tool: "step_0", Params: json.RawMessage(`{}`)},
			{Tool: "step_1", Params: json.RawMessage(`{}`)},
			{Tool: "step_2", Params: json.RawMessage(`{"first":"$step[0].text","second":"$step[1].text"}`)},
		},
	}

	result, err := engine.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}

	var step3Params map[string]string
	if err := json.Unmarshal(capturedParams[2], &step3Params); err != nil {
		t.Fatalf("failed to unmarshal captured params: %v", err)
	}
	if step3Params["first"] != "result_zero" {
		t.Errorf("$step[0].text not substituted: got %q, want %q", step3Params["first"], "result_zero")
	}
	if step3Params["second"] != "result_one" {
		t.Errorf("$step[1].text not substituted: got %q, want %q", step3Params["second"], "result_one")
	}
}

func TestEarlyAbortOnError(t *testing.T) {
	exec := mockExecutor([]struct {
		text    string
		success bool
		err     error
	}{
		{"ok", true, nil},
		{"", false, fmt.Errorf("tool crashed")},
		{"should not run", true, nil},
	})

	engine := NewEngine(exec)
	req := &WorkflowRequest{
		Steps: []Step{
			{Tool: "a", Params: json.RawMessage(`{}`)},
			{Tool: "b", Params: json.RawMessage(`{}`)},
			{Tool: "c", Params: json.RawMessage(`{}`)},
		},
	}

	result, err := engine.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected workflow to fail")
	}
	// Only 2 steps should have run (abort after error on step b)
	if len(result.Steps) != 2 {
		t.Fatalf("expected 2 step results (aborted), got %d", len(result.Steps))
	}
	if result.Steps[1].Success {
		t.Error("step 1 should report failure")
	}
}

func TestEarlyAbortOnFailure(t *testing.T) {
	exec := mockExecutor([]struct {
		text    string
		success bool
		err     error
	}{
		{"first ok", true, nil},
		{"failed check", false, nil},
		{"should not run", true, nil},
	})

	engine := NewEngine(exec)
	req := &WorkflowRequest{
		Steps: []Step{
			{Tool: "a", Params: json.RawMessage(`{}`)},
			{Tool: "b", Params: json.RawMessage(`{}`)},
			{Tool: "c", Params: json.RawMessage(`{}`)},
		},
	}

	result, err := engine.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected workflow to fail on step b success=false")
	}
	if len(result.Steps) != 2 {
		t.Fatalf("expected 2 step results (aborted), got %d", len(result.Steps))
	}
}

func TestEmptyStepsReturnsError(t *testing.T) {
	exec := func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		return "", true, nil
	}

	engine := NewEngine(exec)
	req := &WorkflowRequest{Steps: []Step{}}

	_, err := engine.Run(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty steps")
	}
	if err.Error() != "workflow has no steps" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunFromJSONValid(t *testing.T) {
	exec := func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		return "executed " + toolName, true, nil
	}

	engine := NewEngine(exec)

	input := json.RawMessage(`{"steps":[{"tool":"nmap_scan","params":{"target":"10.0.0.1"}}]}`)
	raw, err := engine.RunFromJSON(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result WorkflowResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(result.Steps) != 1 {
		t.Fatalf("expected 1 step result, got %d", len(result.Steps))
	}
	if result.Steps[0].Text != "executed nmap_scan" {
		t.Errorf("unexpected text: %q", result.Steps[0].Text)
	}
}

func TestRunFromJSONInvalid(t *testing.T) {
	exec := func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		return "", true, nil
	}

	engine := NewEngine(exec)

	tests := []struct {
		name  string
		input json.RawMessage
	}{
		{"malformed json", json.RawMessage(`{not valid}`)},
		{"wrong type", json.RawMessage(`"hello"`)},
		{"incomplete", json.RawMessage(`{"steps":`)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := engine.RunFromJSON(context.Background(), tc.input)
			if err == nil {
				t.Error("expected error for invalid JSON")
			}
		})
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	exec := func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		return "should not run", true, nil
	}

	engine := NewEngine(exec)
	req := &WorkflowRequest{
		Steps: []Step{
			{Tool: "a", Params: json.RawMessage(`{}`)},
		},
	}

	result, err := engine.Run(ctx, req)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on cancellation")
	}
	if result.Success {
		t.Error("expected failure on cancellation")
	}
}
