package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"
)

// Campaign limits, mirroring the sequential engine's hard caps.
const (
	maxCampaignSteps       = 128
	maxParallelGroup       = 16
	maxGotoJumps           = 64
	maxCampaignOutputBytes = 16 * 1024 * 1024
)

// validConditionOps lists every operator accepted in a step condition.
var validConditionOps = map[string]bool{
	"contains": true, "not_contains": true, "equals": true, "not_equals": true,
	"success": true, "failure": true,
	"json_exists": true, "json_not_exists": true, "json_equals": true,
	"json_not_equals": true, "json_contains": true, "json_gt": true, "json_lt": true,
}

// runningCampaign tracks an in-flight campaign for cancellation.
type runningCampaign struct {
	cancel    context.CancelFunc
	done      chan struct{}
	cancelled bool
}

// EnhancedEngine extends the basic engine with parallel steps, conditions,
// goto recovery, checkpointing, resumption, and playbook templates. It backs
// the campaign/* JSON-RPC methods.
type EnhancedEngine struct {
	execute     ToolExecutor
	state       *StateManager
	templates   *TemplateManager
	maxParallel int
	recorder    StepRecorder

	runMu   sync.Mutex
	running map[string]*runningCampaign
}

// NewEnhancedEngine creates an enhanced workflow engine.
func NewEnhancedEngine(exec ToolExecutor, stateDir, templatesDir string, maxParallel int) *EnhancedEngine {
	if maxParallel <= 0 {
		maxParallel = 4
	}
	if maxParallel > 32 {
		maxParallel = 32
	}
	return &EnhancedEngine{
		execute:     exec,
		state:       NewStateManager(stateDir),
		templates:   NewTemplateManager(templatesDir),
		maxParallel: maxParallel,
		running:     make(map[string]*runningCampaign),
	}
}

// RunEnhanced executes an enhanced workflow with all features.
func (e *EnhancedEngine) RunEnhanced(ctx context.Context, req *EnhancedWorkflowRequest) (*WorkflowResult, error) {
	steps := req.Steps

	// If using a template, instantiate it.
	if req.Template != "" {
		instReq, err := e.templates.Instantiate(req.Template, req.Vars)
		if err != nil {
			return nil, fmt.Errorf("instantiate template: %w", err)
		}
		steps = instReq.Steps
	}

	if err := validateSteps(steps); err != nil {
		return nil, err
	}

	workflowID := req.ID
	if workflowID == "" {
		workflowID = GenerateID()
	}
	if err := ValidWorkflowID(workflowID); err != nil {
		return nil, err
	}

	state := &State{
		WorkflowID: workflowID,
		Name:       req.Name,
		Steps:      steps,
		Results:    make(map[string]StepResult),
		NextIndex:  0,
		Status:     "running",
		CreatedAt:  time.Now().Unix(),
	}

	// A workflow re-run with the same ID replaces any stale running entry.
	e.unregisterRun(workflowID)

	ctx, cancel := context.WithCancel(ctx)
	e.registerRun(workflowID, cancel)
	defer e.unregisterRun(workflowID)

	return e.executeSteps(ctx, state)
}

// Resume continues a paused or cancelled workflow from its last checkpoint.
func (e *EnhancedEngine) Resume(ctx context.Context, workflowID string) (*WorkflowResult, error) {
	state, err := e.state.Load(workflowID)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	switch state.Status {
	case "paused", "cancelled", "running":
	default:
		return nil, fmt.Errorf("workflow %s is %s, cannot resume", workflowID, state.Status)
	}
	if err := validateSteps(state.Steps); err != nil {
		return nil, err
	}

	e.unregisterRun(workflowID)

	state.Status = "running"
	ctx, cancel := context.WithCancel(ctx)
	e.registerRun(workflowID, cancel)
	defer e.unregisterRun(workflowID)

	return e.executeSteps(ctx, state)
}

// Cancel aborts a running campaign. It marks the state cancelled; the
// executing goroutine observes the context cancellation and persists its
// checkpoint.
func (e *EnhancedEngine) Cancel(workflowID string) error {
	if err := ValidWorkflowID(workflowID); err != nil {
		return err
	}
	e.runMu.Lock()
	entry, ok := e.running[workflowID]
	if ok {
		entry.cancelled = true
		entry.cancel()
	}
	e.runMu.Unlock()
	if !ok {
		// Not in flight: mark the persisted state directly if it is resumable.
		state, err := e.state.Load(workflowID)
		if err != nil {
			return fmt.Errorf("workflow %s is not running and has no saved state", workflowID)
		}
		if state.Status == "completed" || state.Status == "failed" {
			return fmt.Errorf("workflow %s already %s", workflowID, state.Status)
		}
		state.Status = "cancelled"
		state.UpdatedAt = time.Now().Unix()
		return e.state.Save(state)
	}
	// Give the run a moment to persist its cancelled checkpoint.
	select {
	case <-entry.done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

// Status returns the persisted state of a workflow.
func (e *EnhancedEngine) Status(workflowID string) (*State, error) {
	if err := ValidWorkflowID(workflowID); err != nil {
		return nil, err
	}
	return e.state.Load(workflowID)
}

// ListWorkflows returns all tracked workflow states.
func (e *EnhancedEngine) ListWorkflows() ([]*State, error) {
	return e.state.List()
}

// Templates returns the template manager.
func (e *EnhancedEngine) Templates() *TemplateManager {
	return e.templates
}

// SetRecorder attaches a step recorder that persists structured items
// extracted from step output into the target database.
func (e *EnhancedEngine) SetRecorder(r StepRecorder) {
	e.recorder = r
}

func (e *EnhancedEngine) registerRun(id string, cancel context.CancelFunc) *runningCampaign {
	entry := &runningCampaign{cancel: cancel, done: make(chan struct{})}
	e.runMu.Lock()
	e.running[id] = entry
	e.runMu.Unlock()
	return entry
}

func (e *EnhancedEngine) unregisterRun(id string) {
	e.runMu.Lock()
	entry, ok := e.running[id]
	if ok {
		delete(e.running, id)
	}
	e.runMu.Unlock()
	if ok {
		select {
		case <-entry.done:
		default:
			close(entry.done)
		}
	}
}

func (e *EnhancedEngine) isCancelled(id string) bool {
	e.runMu.Lock()
	defer e.runMu.Unlock()
	entry, ok := e.running[id]
	return ok && entry.cancelled
}

// validateSteps enforces campaign limits before anything executes.
func validateSteps(steps []EnhancedStep) error {
	if len(steps) == 0 {
		return fmt.Errorf("workflow has no steps")
	}
	if len(steps) > maxCampaignSteps {
		return fmt.Errorf("workflow exceeds maximum of %d steps", maxCampaignSteps)
	}
	ids := make(map[string]bool, len(steps))
	var walk func(steps []EnhancedStep, depth int) error
	walk = func(steps []EnhancedStep, depth int) error {
		for i, step := range steps {
			if step.ID != "" {
				if !validStepID(step.ID) {
					return fmt.Errorf("step %d has invalid id %q (allowed: letters, digits, underscore, dash)", i, step.ID)
				}
				if ids[step.ID] {
					return fmt.Errorf("duplicate step id %q", step.ID)
				}
				ids[step.ID] = true
			}
			if len(step.Parallel) > 0 {
				if depth > 0 {
					return fmt.Errorf("nested parallel steps are not supported")
				}
				if step.Tool != "" {
					return fmt.Errorf("step %d cannot set both tool and parallel", i)
				}
				if len(step.Parallel) > maxParallelGroup {
					return fmt.Errorf("parallel group at step %d exceeds %d steps", i, maxParallelGroup)
				}
				if step.OnFail != "" && step.OnFail != "continue" && step.OnFail != "stop" && !strings.HasPrefix(step.OnFail, "goto:") {
					return fmt.Errorf("step %d has invalid on_fail %q", i, step.OnFail)
				}
				if err := walk(step.Parallel, depth+1); err != nil {
					return err
				}
				continue
			}
			if strings.TrimSpace(step.Tool) == "" {
				return fmt.Errorf("step %d has no tool", i)
			}
			if len(step.Params) > 0 {
				var object map[string]json.RawMessage
				if err := json.Unmarshal(step.Params, &object); err != nil || object == nil {
					return fmt.Errorf("step %d params must be a JSON object", i)
				}
			}
			if step.OnFail != "" && step.OnFail != "continue" && step.OnFail != "stop" && !strings.HasPrefix(step.OnFail, "goto:") {
				return fmt.Errorf("step %d has invalid on_fail %q (allowed: stop, continue, goto:<step_id>)", i, step.OnFail)
			}
			if step.Condition != nil {
				if !validConditionOps[step.Condition.Op] {
					return fmt.Errorf("step %d has invalid condition op %q", i, step.Condition.Op)
				}
			}
			for j, rule := range step.Record {
				if err := validateRecordRule(rule); err != nil {
					return fmt.Errorf("step %d record rule %d: %w", i, j, err)
				}
			}
			for _, id := range step.MITRE {
				if !ValidMITREID(id) {
					return fmt.Errorf("step %d has invalid MITRE technique ID %q (expected e.g. T1613 or T1552.007)", i, id)
				}
			}
		}
		return nil
	}
	return walk(steps, 0)
}

func validStepID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// parseGoto extracts the target step ID from an on_fail value.
func parseGoto(onFail string) (string, bool) {
	if !strings.HasPrefix(onFail, "goto:") {
		return "", false
	}
	target := strings.TrimSpace(strings.TrimPrefix(onFail, "goto:"))
	if target == "" {
		return "", false
	}
	return target, true
}

func findStepIndex(steps []EnhancedStep, id string) int {
	for i, step := range steps {
		if step.ID == id {
			return i
		}
	}
	return -1
}

func (e *EnhancedEngine) executeSteps(ctx context.Context, state *State) (*WorkflowResult, error) {
	var allResults []StepResult
	outputBytes := 0

	// Replay already-completed results into the indexed slice.
	for i := 0; i < state.NextIndex && i < len(state.Steps); i++ {
		stepID := stepIDAt(state.Steps, i)
		if r, ok := state.Results[stepID]; ok {
			allResults = append(allResults, r)
			outputBytes += len(r.Text)
		}
	}

	i := state.NextIndex
	for i < len(state.Steps) {
		select {
		case <-ctx.Done():
			state.Status = "paused"
			if e.isCancelled(state.WorkflowID) {
				state.Status = "cancelled"
			}
			state.NextIndex = i
			state.UpdatedAt = time.Now().Unix()
			if err := e.state.Save(state); err != nil {
				log.Printf("workflow: checkpoint save failed: %v", err)
			}
			return buildResult(state, allResults, false), ctx.Err()
		default:
		}

		step := state.Steps[i]
		stepID := stepIDAt(state.Steps, i)

		// Evaluate condition.
		if step.Condition != nil && !EvaluateConditionWithIndexed(step.Condition, state.Results, allResults) {
			r := StepResult{Tool: step.Tool, ID: stepID, Success: true, Skipped: true, Text: "skipped: condition not met"}
			allResults = append(allResults, r)
			state.Results[stepID] = r
			state.NextIndex = i + 1
			i++
			continue
		}

		if len(step.Parallel) > 0 {
			results, failed := e.RunParallel(ctx, step.Parallel, state.Results, allResults)
			for idx, r := range results {
				r.ID = parallelStepID(step.Parallel, idx, stepID)
				if r.Success {
					e.recordStep(state, step.Parallel[idx], r.ID, &r)
					state.aggregateMITRE(step.Parallel[idx])
					state.Results[r.ID] = r
				}
				allResults = append(allResults, r)
				outputBytes += len(r.Text)
			}
			if outputBytes > maxCampaignOutputBytes {
				return e.fail(state, allResults, i, fmt.Sprintf("campaign output exceeds %d MiB", maxCampaignOutputBytes/(1024*1024))), nil
			}
			// Cancellation mid-group pauses rather than fails, so the group
			// re-runs on resume.
			if ctx.Err() != nil {
				return e.pause(ctx, state, allResults, i), ctx.Err()
			}
			if failed > 0 {
				if target, ok := parseGoto(step.OnFail); ok {
					if err := e.jump(state, allResults, target, &i); err != nil {
						return e.fail(state, allResults, i, err.Error()), nil
					}
					continue
				}
				if step.OnFail != "continue" {
					return e.fail(state, allResults, i, fmt.Sprintf("%d parallel step(s) failed", failed)), nil
				}
			}
		} else {
			params, err := substituteCampaignVars(step.Params, state.Results, allResults)
			if err != nil {
				return e.fail(state, allResults, i, err.Error()), nil
			}
			text, success, execErr := e.execute(ctx, step.Tool, params)

			// Cancellation or timeout mid-step pauses rather than fails; the
			// interrupted step re-runs from its checkpoint on resume.
			if ctx.Err() != nil {
				return e.pause(ctx, state, allResults, i), ctx.Err()
			}

			r := StepResult{Tool: step.Tool, ID: stepID, Success: success, Text: text}
			if execErr != nil {
				r.Success = false
				r.Text = fmt.Sprintf("execution error: %s", execErr.Error())
			}
			allResults = append(allResults, r)
			state.Results[stepID] = r
			outputBytes += len(r.Text)

			if outputBytes > maxCampaignOutputBytes {
				return e.fail(state, allResults, i, fmt.Sprintf("campaign output exceeds %d MiB", maxCampaignOutputBytes/(1024*1024))), nil
			}

			if !r.Success {
				if target, ok := parseGoto(step.OnFail); ok {
					if err := e.jump(state, allResults, target, &i); err != nil {
						return e.fail(state, allResults, i, err.Error()), nil
					}
					continue
				}
				if step.OnFail != "continue" {
					// "" and "stop"
					return e.fail(state, allResults, i, ""), nil
				}
			}

			if r.Success {
				e.recordStep(state, step, stepID, &r)
				state.Results[stepID] = r
				state.aggregateMITRE(step)
				// recordStep may annotate the result; refresh the copy in
				// the result list.
				allResults[len(allResults)-1] = r
			}
		}

		state.NextIndex = i + 1
		i++

		// Checkpoint every step.
		state.UpdatedAt = time.Now().Unix()
		if err := e.state.Save(state); err != nil {
			log.Printf("workflow: checkpoint save failed: %v", err)
		}
	}

	state.Status = "completed"
	state.UpdatedAt = time.Now().Unix()
	if err := e.state.Save(state); err != nil {
		log.Printf("workflow: checkpoint save failed: %v", err)
	}
	return buildResult(state, allResults, true), nil
}

// jump moves execution to the step with the given ID, enforcing the goto budget.
func (e *EnhancedEngine) jump(state *State, allResults []StepResult, target string, i *int) error {
	if state.JumpsUsed >= maxGotoJumps {
		return fmt.Errorf("campaign exceeded %d goto recovery jumps (possible loop)", maxGotoJumps)
	}
	idx := findStepIndex(state.Steps, target)
	if idx < 0 {
		return fmt.Errorf("on_fail goto target step %q not found", target)
	}
	state.JumpsUsed++
	state.NextIndex = idx
	state.UpdatedAt = time.Now().Unix()
	if err := e.state.Save(state); err != nil {
		log.Printf("workflow: checkpoint save failed: %v", err)
	}
	*i = idx
	return nil
}

// pause checkpoints a campaign that was cancelled or timed out mid-step. The
// interrupted step re-runs on resume because NextIndex points at it.
func (e *EnhancedEngine) pause(ctx context.Context, state *State, allResults []StepResult, i int) *WorkflowResult {
	state.Status = "paused"
	if e.isCancelled(state.WorkflowID) {
		state.Status = "cancelled"
	}
	state.NextIndex = i
	state.Error = fmt.Sprintf("interrupted: %v", ctx.Err())
	state.UpdatedAt = time.Now().Unix()
	if err := e.state.Save(state); err != nil {
		log.Printf("workflow: checkpoint save failed: %v", err)
	}
	return buildResult(state, allResults, false)
}

func (e *EnhancedEngine) fail(state *State, allResults []StepResult, i int, msg string) *WorkflowResult {
	state.Status = "failed"
	state.NextIndex = i + 1
	state.Error = msg
	state.UpdatedAt = time.Now().Unix()
	if err := e.state.Save(state); err != nil {
		log.Printf("workflow: checkpoint save failed: %v", err)
	}
	result := buildResult(state, allResults, false)
	if msg != "" {
		result.Steps = append(result.Steps, StepResult{Tool: "campaign", Success: false, Text: msg})
	}
	return result
}

func stepIDAt(steps []EnhancedStep, i int) string {
	if steps[i].ID != "" {
		return steps[i].ID
	}
	return fmt.Sprintf("step_%d", i)
}

func parallelStepID(steps []EnhancedStep, idx int, parentID string) string {
	if steps[idx].ID != "" {
		return steps[idx].ID
	}
	return fmt.Sprintf("%s_parallel_%d", parentID, idx)
}

func buildResult(state *State, results []StepResult, success bool) *WorkflowResult {
	return &WorkflowResult{
		WorkflowID: state.WorkflowID,
		Status:     state.Status,
		Steps:      results,
		Success:    success,
		MITRE:      state.Techniques,
	}
}

// RunFromJSON is the JSON-RPC handler for campaign/run.
func (e *EnhancedEngine) RunFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var req EnhancedWorkflowRequest
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid campaign params: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("campaign must contain exactly one JSON object")
	}
	result, err := e.RunEnhanced(ctx, &req)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal campaign result: %w", err)
	}
	return data, nil
}

// ResumeFromJSON is the JSON-RPC handler for campaign/resume.
func (e *EnhancedEngine) ResumeFromJSON(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	var req struct {
		WorkflowID string `json:"workflow_id"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if req.WorkflowID == "" {
		return nil, fmt.Errorf("workflow_id is required")
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

// CancelFromJSON is the JSON-RPC handler for campaign/cancel.
func (e *EnhancedEngine) CancelFromJSON(params json.RawMessage) (json.RawMessage, error) {
	var req struct {
		WorkflowID string `json:"workflow_id"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if req.WorkflowID == "" {
		return nil, fmt.Errorf("workflow_id is required")
	}
	if err := e.Cancel(req.WorkflowID); err != nil {
		return nil, err
	}
	return json.RawMessage(`{"cancelled":true}`), nil
}

// StatusFromJSON is the JSON-RPC handler for campaign/status.
func (e *EnhancedEngine) StatusFromJSON(params json.RawMessage) (json.RawMessage, error) {
	var req struct {
		WorkflowID string `json:"workflow_id"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if req.WorkflowID == "" {
		return nil, fmt.Errorf("workflow_id is required")
	}
	state, err := e.Status(req.WorkflowID)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal state: %w", err)
	}
	return data, nil
}

// ListFromJSON is the JSON-RPC handler for campaign/list.
func (e *EnhancedEngine) ListFromJSON(params json.RawMessage) (json.RawMessage, error) {
	_ = params
	states, err := e.ListWorkflows()
	if err != nil {
		return nil, err
	}
	if states == nil {
		states = []*State{}
	}
	data, err := json.Marshal(states)
	if err != nil {
		return nil, fmt.Errorf("marshal states: %w", err)
	}
	return data, nil
}

// TemplatesFromJSON is the JSON-RPC handler for campaign/templates.
func (e *EnhancedEngine) TemplatesFromJSON(params json.RawMessage) (json.RawMessage, error) {
	_ = params
	templates := e.templates.List()
	if templates == nil {
		templates = []*Template{}
	}
	data, err := json.Marshal(templates)
	if err != nil {
		return nil, fmt.Errorf("marshal templates: %w", err)
	}
	return data, nil
}

// GetTemplateFromJSON is the JSON-RPC handler for campaign/template/get.
func (e *EnhancedEngine) GetTemplateFromJSON(params json.RawMessage) (json.RawMessage, error) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	t, ok := e.templates.Get(req.Name)
	if !ok {
		return nil, fmt.Errorf("template %q not found", req.Name)
	}
	data, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("marshal template: %w", err)
	}
	return data, nil
}

// SaveTemplateFromJSON is the JSON-RPC handler for campaign/template/save.
// It persists a playbook for reuse via campaign/run with {"template": name}.
func (e *EnhancedEngine) SaveTemplateFromJSON(params json.RawMessage) (json.RawMessage, error) {
	var t Template
	decoder := json.NewDecoder(bytes.NewReader(params))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&t); err != nil {
		return nil, fmt.Errorf("invalid template: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("template must contain exactly one JSON object")
	}
	if t.Name == "" {
		return nil, fmt.Errorf("template name is required")
	}
	if err := validateSteps(t.Steps); err != nil {
		return nil, fmt.Errorf("template steps invalid: %w", err)
	}
	if err := e.templates.Save(&t); err != nil {
		return nil, err
	}
	return json.RawMessage(`{"saved":true}`), nil
}

// ScheduleFromJSON is the JSON-RPC handler for scheduling workflows.
func (e *EnhancedEngine) ScheduleFromJSON(params json.RawMessage) (json.RawMessage, error) {
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
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return data, nil
}
