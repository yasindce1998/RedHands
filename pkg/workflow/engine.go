package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

const maxWorkflowOutputBytes = 16 * 1024 * 1024

// NewEngine creates a workflow engine with the given tool executor.
func NewEngine(exec ToolExecutor) *Engine {
	return &Engine{execute: exec}
}

// RunFromJSON satisfies mcp.WorkflowRunner — unmarshals params and runs.
func (e *Engine) RunFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var req WorkflowRequest
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid workflow params: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("workflow must contain exactly one JSON object")
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
	if len(req.Steps) > 128 {
		return nil, fmt.Errorf("workflow exceeds maximum of 128 steps")
	}
	// Validate the entire plan before running its first potentially mutating step.
	for i, step := range req.Steps {
		if strings.TrimSpace(step.Tool) == "" {
			return nil, fmt.Errorf("step %d has no tool", i)
		}
		if len(step.Params) == 0 {
			continue
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(step.Params, &object); err != nil || object == nil {
			return nil, fmt.Errorf("step %d params must be a JSON object", i)
		}
	}

	results := make([]StepResult, 0, len(req.Steps))
	outputBytes := 0

	for i, step := range req.Steps {
		select {
		case <-ctx.Done():
			return &WorkflowResult{Steps: results, Success: false}, ctx.Err()
		default:
		}

		params, err := substituteVarsBounded(step.Params, results, i)
		if err != nil {
			return &WorkflowResult{Steps: results, Success: false}, err
		}

		text, success, err := e.execute(ctx, step.Tool, params)
		if err != nil {
			results = append(results, StepResult{
				Tool:    step.Tool,
				Success: false,
				Text:    fmt.Sprintf("execution error: %s", err.Error()),
			})
			return &WorkflowResult{Steps: results, Success: false}, nil
		}
		if len(text) > maxWorkflowOutputBytes-outputBytes {
			return &WorkflowResult{Steps: results, Success: false}, fmt.Errorf("workflow output exceeds 16 MiB; no further steps executed")
		}
		outputBytes += len(text)

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
	data, err := substituteVarsBounded(params, results, currentIdx)
	if err != nil {
		return params
	}
	return data
}

func substituteVarsBounded(params json.RawMessage, results []StepResult, currentIdx int) (json.RawMessage, error) {
	if len(params) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	pairs := make([]string, 0, 2*(len(results)+1))
	if currentIdx > 0 && len(results) > 0 {
		pairs = append(pairs, "$prev.text", results[len(results)-1].Text)
	}
	for i, r := range results {
		pairs = append(pairs, fmt.Sprintf("$step[%d].text", i), r.Text)
	}
	replacer := strings.NewReplacer(pairs...)
	remaining := 10 * 1024 * 1024
	var replace func(any) (any, error)
	replace = func(v any) (any, error) {
		switch typed := v.(type) {
		case string:
			writer := &substitutionWriter{remaining: &remaining}
			if _, err := replacer.WriteString(writer, typed); err != nil {
				return nil, err
			}
			return writer.String(), nil
		case []any:
			for i, item := range typed {
				value, err := replace(item)
				if err != nil {
					return nil, err
				}
				typed[i] = value
			}
		case map[string]any:
			for key, item := range typed {
				value, err := replace(item)
				if err != nil {
					return nil, err
				}
				typed[key] = value
			}
		}
		return v, nil
	}
	value, err := replace(value)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) > 10*1024*1024 {
		return nil, fmt.Errorf("substituted workflow parameters exceed 10 MiB")
	}
	return data, nil
}

type substitutionWriter struct {
	strings.Builder
	remaining *int
}

func (w *substitutionWriter) Write(p []byte) (int, error) { return w.WriteString(string(p)) }
func (w *substitutionWriter) WriteString(text string) (int, error) {
	if len(text) > *w.remaining {
		return 0, fmt.Errorf("substituted workflow parameters exceed 10 MiB")
	}
	*w.remaining -= len(text)
	return w.Builder.WriteString(text)
}

// Used by the separate, currently inactive enhanced workflow implementation.
func escapeJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
