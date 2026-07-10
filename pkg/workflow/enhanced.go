package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// EnhancedEngine extends the basic engine with parallel steps, conditions, and state.
type EnhancedEngine struct {
	execute     ToolExecutor
	state       *StateManager
	templates   *TemplateManager
	maxParallel int
}

// NewEnhancedEngine creates an enhanced workflow engine.
func NewEnhancedEngine(exec ToolExecutor, stateDir, templatesDir string, maxParallel int) *EnhancedEngine {
	if maxParallel <= 0 {
		maxParallel = 4
	}
	return &EnhancedEngine{
		execute:     exec,
		state:       NewStateManager(stateDir),
		templates:   NewTemplateManager(templatesDir),
		maxParallel: maxParallel,
	}
}

// RunEnhanced executes an enhanced workflow with all features.
func (e *EnhancedEngine) RunEnhanced(ctx context.Context, req *EnhancedWorkflowRequest) (*WorkflowResult, error) {
	steps := req.Steps

	// If using a template, instantiate it
	if req.Template != "" {
		instReq, err := e.templates.Instantiate(req.Template, req.Vars)
		if err != nil {
			return nil, fmt.Errorf("instantiate template: %w", err)
		}
		steps = instReq.Steps
	}

	if len(steps) == 0 {
		return nil, fmt.Errorf("workflow has no steps")
	}

	workflowID := req.ID
	if workflowID == "" {
		workflowID = GenerateID()
	}

	state := &State{
		WorkflowID: workflowID,
		Name:       req.Name,
		Steps:      steps,
		Results:    make(map[string]StepResult),
		NextIndex:  0,
		Status:     "running",
	}

	return e.executeSteps(ctx, state)
}

// Resume continues a paused workflow from its last checkpoint.
func (e *EnhancedEngine) Resume(ctx context.Context, workflowID string) (*WorkflowResult, error) {
	state, err := e.state.Load(workflowID)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	if state.Status != "paused" && state.Status != "running" {
		return nil, fmt.Errorf("workflow %s is %s, cannot resume", workflowID, state.Status)
	}

	state.Status = "running"
	return e.executeSteps(ctx, state)
}

// ListWorkflows returns all tracked workflow states.
func (e *EnhancedEngine) ListWorkflows() ([]*State, error) {
	return e.state.List()
}

// Templates returns the template manager.
func (e *EnhancedEngine) Templates() *TemplateManager {
	return e.templates
}

func (e *EnhancedEngine) executeSteps(ctx context.Context, state *State) (*WorkflowResult, error) {
	var allResults []StepResult

	// Replay already-completed results into the indexed slice
	for i := 0; i < state.NextIndex && i < len(state.Steps); i++ {
		stepID := state.Steps[i].ID
		if stepID == "" {
			stepID = fmt.Sprintf("step_%d", i)
		}
		if r, ok := state.Results[stepID]; ok {
			allResults = append(allResults, r)
		}
	}

	for i := state.NextIndex; i < len(state.Steps); i++ {
		select {
		case <-ctx.Done():
			state.Status = "paused"
			state.NextIndex = i
			_ = e.state.Save(state)
			return buildResult(allResults, false), ctx.Err()
		default:
		}

		step := state.Steps[i]
		stepID := step.ID
		if stepID == "" {
			stepID = fmt.Sprintf("step_%d", i)
		}

		// Evaluate condition
		if step.Condition != nil && !EvaluateCondition(step.Condition, state.Results) {
			r := StepResult{Tool: step.Tool, Success: true, Text: "skipped: condition not met"}
			allResults = append(allResults, r)
			state.Results[stepID] = r
			state.NextIndex = i + 1
			continue
		}

		var results []StepResult
		var err error

		if len(step.Parallel) > 0 {
			results, err = e.RunParallel(ctx, step.Parallel, state.Results, allResults)
			if err != nil {
				state.Status = "failed"
				state.Error = err.Error()
				_ = e.state.Save(state)
				return buildResult(allResults, false), nil
			}
			allResults = append(allResults, results...)
		} else {
			params := substituteVarsFromMap(step.Params, state.Results, allResults)
			text, success, execErr := e.execute(ctx, step.Tool, params)

			r := StepResult{Tool: step.Tool, Success: success, Text: text}
			if execErr != nil {
				r.Success = false
				r.Text = fmt.Sprintf("execution error: %s", execErr.Error())
			}
			allResults = append(allResults, r)
			state.Results[stepID] = r

			if !r.Success {
				switch step.OnFail {
				case "continue":
					// Keep going
				case "":
					fallthrough
				case "stop":
					state.Status = "failed"
					state.NextIndex = i + 1
					_ = e.state.Save(state)
					return buildResult(allResults, false), nil
				default:
					// "goto:step_id" not implemented in first pass
					state.Status = "failed"
					state.NextIndex = i + 1
					_ = e.state.Save(state)
					return buildResult(allResults, false), nil
				}
			}
		}

		state.NextIndex = i + 1

		// Checkpoint every step
		_ = e.state.Save(state)
	}

	state.Status = "completed"
	_ = e.state.Save(state)
	return buildResult(allResults, true), nil
}

func buildResult(results []StepResult, success bool) *WorkflowResult {
	return &WorkflowResult{Steps: results, Success: success}
}

// RunEnhancedFromJSON is the JSON-RPC handler for enhanced workflows.
func (e *EnhancedEngine) RunEnhancedFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var req EnhancedWorkflowRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid workflow params: %w", err)
	}
	result, err := e.RunEnhanced(ctx, &req)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal workflow result: %w", err)
	}
	return data, nil
}

// ResumeFromJSON is the JSON-RPC handler for resuming workflows.
func (e *EnhancedEngine) ResumeFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var req struct {
		WorkflowID string `json:"workflow_id"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	result, err := e.Resume(ctx, req.WorkflowID)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return data, nil
}

// ListFromJSON is the JSON-RPC handler for listing workflows.
func (e *EnhancedEngine) ListFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	states, err := e.ListWorkflows()
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(states)
	if err != nil {
		return nil, fmt.Errorf("marshal states: %w", err)
	}
	return data, nil
}

// ScheduleFromJSON is the JSON-RPC handler for scheduling workflows.
func (e *EnhancedEngine) ScheduleFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var entry ScheduleEntry
	if err := json.Unmarshal(params, &entry); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	scheduler := NewScheduler(e, "")
	if err := scheduler.Add(&entry); err != nil {
		return nil, err
	}

	resp := map[string]interface{}{
		"id":       entry.ID,
		"next_run": time.Unix(entry.NextRun, 0).Format(time.RFC3339),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// TemplatesFromJSON is the JSON-RPC handler for listing templates.
func (e *EnhancedEngine) TemplatesFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	templates := e.templates.List()
	data, err := json.Marshal(templates)
	if err != nil {
		return nil, fmt.Errorf("marshal templates: %w", err)
	}
	return data, nil
}
