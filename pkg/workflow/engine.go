package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Step represents a single tool execution in a workflow.
type Step struct {
	Tool   string          `json:"tool"`
	Params json.RawMessage `json:"params"`
}

// WorkflowRequest is the input to workflow/run.
type WorkflowRequest struct {
	Steps []Step `json:"steps"`
}

// StepResult holds the result from a single step.
type StepResult struct {
	Tool    string `json:"tool"`
	Success bool   `json:"success"`
	Text    string `json:"text"`
}

// WorkflowResult is the combined output of all steps.
type WorkflowResult struct {
	Steps   []StepResult `json:"steps"`
	Success bool         `json:"success"`
}

// ToolExecutor is the function signature for executing a tool by name.
type ToolExecutor func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error)

// Engine orchestrates sequential tool execution with variable substitution.
type Engine struct {
	execute ToolExecutor
}

// NewEngine creates a workflow engine with the given tool executor.
func NewEngine(exec ToolExecutor) *Engine {
	return &Engine{execute: exec}
}

// RunFromJSON satisfies mcp.WorkflowRunner — unmarshals params and runs.
func (e *Engine) RunFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var req WorkflowRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid workflow params: %w", err)
	}
	result, err := e.Run(ctx, &req)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal workflow result: %w", err)
	}
	return data, nil
}

// Run executes all steps sequentially, substituting variables between steps.
func (e *Engine) Run(ctx context.Context, req *WorkflowRequest) (*WorkflowResult, error) {
	if len(req.Steps) == 0 {
		return nil, fmt.Errorf("workflow has no steps")
	}

	results := make([]StepResult, 0, len(req.Steps))

	for i, step := range req.Steps {
		select {
		case <-ctx.Done():
			return &WorkflowResult{Steps: results, Success: false}, ctx.Err()
		default:
		}

		params := substituteVars(step.Params, results, i)

		text, success, err := e.execute(ctx, step.Tool, params)
		if err != nil {
			results = append(results, StepResult{
				Tool:    step.Tool,
				Success: false,
				Text:    fmt.Sprintf("execution error: %s", err.Error()),
			})
			return &WorkflowResult{Steps: results, Success: false}, nil
		}

		results = append(results, StepResult{
			Tool:    step.Tool,
			Success: success,
			Text:    text,
		})

		if !success {
			return &WorkflowResult{Steps: results, Success: false}, nil
		}
	}

	return &WorkflowResult{Steps: results, Success: true}, nil
}

// substituteVars replaces $prev.text and $step[N].text in params.
func substituteVars(params json.RawMessage, results []StepResult, currentIdx int) json.RawMessage {
	s := string(params)

	// Replace $prev.text with previous step's output
	if currentIdx > 0 && len(results) > 0 {
		prev := results[len(results)-1]
		s = strings.ReplaceAll(s, "$prev.text", escapeJSON(prev.Text))
	}

	// Replace $step[N].text with specific step output
	for i, r := range results {
		placeholder := fmt.Sprintf("$step[%d].text", i)
		s = strings.ReplaceAll(s, placeholder, escapeJSON(r.Text))
	}

	return json.RawMessage(s)
}

// escapeJSON escapes a string for safe inclusion in a JSON string value.
func escapeJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	// Remove surrounding quotes since it's being inserted into an existing JSON string
	return string(b[1 : len(b)-1])
}
