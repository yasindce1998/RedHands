package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yasindce1998/redhands/pkg/mcp"
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

// ErrAlreadyRunning is returned (wrapped) when a campaign cannot start or
// resume because another process or goroutine holds its run lock. Idempotent
// callers match on it with errors.Is to treat a duplicate start as a no-op.
var ErrAlreadyRunning = errors.New("already running")

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

	// engagementCheck validates an engagement binding before a campaign
	// starts; it is supplied by the application layer.
	engagementCheck func(name string) error

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
	prep, err := e.prepareRun(req)
	if err != nil {
		return nil, err
	}
	defer prep.lock.release()

	ctx, cancel := context.WithCancel(ctx)
	e.registerRun(prep.state.WorkflowID, cancel)
	defer e.unregisterRun(prep.state.WorkflowID)

	return e.executeSteps(ctx, prep.state)
}

// preparedRun is a validated, locked, and durably-started campaign. The
// initial running-state save in prepareRun is the durable record that a
// task exists; it happens before any caller is answered.
type preparedRun struct {
	state *State
	lock  *runLock
}

// prepareRun validates the request, takes the per-campaign single-writer
// lock, and persists the initial running state. Callers must release
// prep.lock when execution ends (RunEnhanced synchronously, StartAsync's
// background goroutine otherwise).
func (e *EnhancedEngine) prepareRun(req *EnhancedWorkflowRequest) (*preparedRun, error) {
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

	if err := e.checkEngagement(req.Engagement); err != nil {
		return nil, err
	}

	// Single writer per campaign: a non-blocking exclusive lock on the
	// campaign's lock file. A second start with the same ID — from this
	// process or a replica sharing the state dir — fails fast instead of
	// silently replacing the running entry and corrupting checkpoints.
	// The in-process running map is checked first: on platforms where the
	// advisory lock is a no-op (non-unix) it is the only same-process
	// guard, and on unix it makes duplicate starts fail before touching
	// the lock file at all.
	if e.isRunningLocally(workflowID) {
		return nil, fmt.Errorf("campaign %s is %w", workflowID, ErrAlreadyRunning)
	}
	lock, err := acquireRunLock(e.state.Dir(), workflowID)
	if err != nil {
		return nil, err
	}

	state := &State{
		WorkflowID: workflowID,
		Name:       req.Name,
		Engagement: req.Engagement,
		Steps:      steps,
		Results:    make(map[string]StepResult),
		NextIndex:  0,
		Status:     "running",
		CreatedAt:  time.Now().Unix(),
	}

	// Persist the running state up front. This clears any stale terminal
	// marker (e.g. "cancelled" from a previous run of this ID) that the
	// cross-replica cancel check would otherwise trip over, and makes the
	// campaign visible to Cancel from other replicas before the first
	// checkpoint.
	if err := e.state.Save(state); err != nil {
		lock.release()
		return nil, fmt.Errorf("save initial state: %w", err)
	}
	return &preparedRun{state: state, lock: lock}, nil
}

// StartAsync durably starts a campaign in the background (the async path
// of campaign/start and the campaign_start tool). The initial running
// state is persisted synchronously, BEFORE StartAsync returns, so a task
// id handed to the client always addresses an existing checkpoint. The
// execution itself runs on ctx in a goroutine that owns the run lock; ctx
// must be detached from any request lifetime (the protocol layer passes a
// cancellation-free context that keeps the caller's context values).
//
// Idempotency: when a campaign with the same id is already in flight
// (single-writer lock held elsewhere), StartAsync does not error; it
// returns the existing workflow id with alreadyRunning=true so the caller
// can answer a duplicate start with the live task.
func (e *EnhancedEngine) StartAsync(ctx context.Context, req *EnhancedWorkflowRequest) (workflowID string, alreadyRunning bool, err error) {
	prep, err := e.prepareRun(req)
	if err != nil {
		if errors.Is(err, ErrAlreadyRunning) && req.ID != "" {
			// A duplicate start of a named campaign addresses the live
			// task. (A generated id colliding with a running campaign is
			// astronomically unlikely; treat it as a plain error.)
			return req.ID, true, nil
		}
		return "", false, err
	}

	ctx, cancel := context.WithCancel(ctx)
	// Register synchronously: on platforms where the advisory lock is a
	// no-op (non-unix), the in-process running map is the only
	// double-start guard, so it must be populated before this call
	// returns.
	e.registerRun(prep.state.WorkflowID, cancel)
	go func() {
		defer prep.lock.release()
		defer cancel()
		defer e.unregisterRun(prep.state.WorkflowID)
		// The result is durably recorded in the state (including
		// FinalResult on completion); an asynchronous caller consumes it
		// via tasks/get.
		_, _ = e.executeSteps(ctx, prep.state)
	}()
	return prep.state.WorkflowID, false, nil
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
	// The engagement binding is re-validated on resume: the operator may
	// have switched engagements between runs.
	if err := e.checkEngagement(state.Engagement); err != nil {
		return nil, err
	}

	// Single writer per campaign: resuming a campaign another process (or
	// goroutine) is still executing fails fast. A stale "running" state left
	// behind by a crashed process holds no lock and resumes normally.
	lock, err := acquireRunLock(e.state.Dir(), workflowID)
	if err != nil {
		return nil, err
	}
	defer lock.release()

	state.Status = "running"
	// Clear the persisted terminal marker (paused/cancelled) before
	// executing so the cross-replica cancel check does not trip over the
	// very marker this resume is recovering from.
	state.UpdatedAt = time.Now().Unix()
	if err := e.state.Save(state); err != nil {
		return nil, fmt.Errorf("save resumed state: %w", err)
	}
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

// SetEngagementCheck attaches the validator used when a campaign binds to a
// named engagement. The application layer resolves engagement names/IDs and
// active state; the engine calls it before any step executes.
func (e *EnhancedEngine) SetEngagementCheck(check func(name string) error) {
	e.engagementCheck = check
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

// isRunningLocally reports whether a run with this workflow ID is currently
// executing in this process.
func (e *EnhancedEngine) isRunningLocally(workflowID string) bool {
	e.runMu.Lock()
	defer e.runMu.Unlock()
	_, ok := e.running[workflowID]
	return ok
}

func (e *EnhancedEngine) isCancelled(id string) bool {
	e.runMu.Lock()
	defer e.runMu.Unlock()
	entry, ok := e.running[id]
	return ok && entry.cancelled
}

// persistedCancelled reports whether the on-disk checkpoint for a campaign has
// been marked cancelled. Cancel writes that marker when the run is not local
// to the cancelling process, so the executing replica observes it at its next
// checkpoint. Read errors (missing state, transient I/O) report not
// cancelled: execution must not stall on a state file it cannot read.
func (e *EnhancedEngine) persistedCancelled(workflowID string) bool {
	state, err := e.state.Load(workflowID)
	if err != nil {
		return false
	}
	return state.Status == "cancelled"
}

// checkEngagement validates an optional engagement binding. An empty name
// means the campaign is unbound. Every step still passes the scope
// middleware; the binding makes the intended engagement an explicit
// contract that fails fast instead of running against the wrong scope.
func (e *EnhancedEngine) checkEngagement(name string) error {
	if name == "" {
		return nil
	}
	if e.engagementCheck == nil {
		return fmt.Errorf("engagement binding %q rejected: engagement scoping is not configured on this server", name)
	}
	return e.engagementCheck(name)
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
	if err := walk(steps, 0); err != nil {
		return err
	}
	// Conditions are validated in a second pass, once every step ID
	// (including parallel sub-step IDs) has been collected, so forward
	// references resolve.
	return validateConditions(steps, ids)
}

// validateConditions checks every condition in the plan once all step IDs are
// known. The operator must be recognized, and the condition's Step reference
// must resolve: a declared step ID (including parallel sub-step IDs),
// "$prev"/"prev", or a decimal index within range of the campaign's indexed
// results. A typo'd ID or out-of-range index would otherwise silently
// evaluate false at runtime and skip the step, so it is rejected here.
func validateConditions(steps []EnhancedStep, ids map[string]bool) error {
	total := countIndexedResults(steps)
	var visit func(steps []EnhancedStep) error
	visit = func(steps []EnhancedStep) error {
		for i, step := range steps {
			if step.Condition != nil {
				label := step.ID
				if label == "" {
					label = fmt.Sprintf("%d", i)
				}
				if !validConditionOps[step.Condition.Op] {
					return fmt.Errorf("step %s has invalid condition op %q", label, step.Condition.Op)
				}
				if !validConditionRef(step.Condition.Step, ids, total) {
					return fmt.Errorf("step %s condition references unknown step %q (allowed: a declared step id, $prev/prev, or an index 0..%d)", label, step.Condition.Step, total-1)
				}
			}
			if len(step.Parallel) > 0 {
				if err := visit(step.Parallel); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(steps)
}

// countIndexedResults returns the number of indexed step results a campaign
// produces: one per plain step, one per parallel sub-step.
func countIndexedResults(steps []EnhancedStep) int {
	n := 0
	for _, step := range steps {
		if len(step.Parallel) > 0 {
			n += len(step.Parallel)
		} else {
			n++
		}
	}
	return n
}

// validConditionRef reports whether a condition's Step reference can resolve.
func validConditionRef(ref string, ids map[string]bool, total int) bool {
	if ref == "" || ref == "$prev" || ref == "prev" {
		return true
	}
	if ids[ref] {
		return true
	}
	if idx, err := strconv.Atoi(ref); err == nil && idx >= 0 && idx < total {
		return true
	}
	return false
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

			// MRTR approval-gate resolution: when this campaign was paused
			// on an approval gate, consume the operator's tasks/update
			// decision before (re)running the gated step. An approval
			// re-runs the step with a one-call approval bypass carried in
			// the execution context (never in the step params); a denial
			// records a failed step and applies the step's on_fail policy
			// through the shared failure path below. A stale or unanswered
			// gate falls through and re-trips below, pausing again with a
			// fresh request id.
			execCtx := ctx
			denied := false
			if pa := state.PendingApproval; pa != nil {
				state.PendingApproval = nil
				if pa.StepID == stepID {
					approved, responded := pa.Decision()
					if responded {
						if approved {
							// The approval was obtained through the
							// tasks protocol (tasks/update on a
							// task-tracked campaign), so the re-run
							// re-establishes the tasks-extension marker on
							// the execution context itself: the resume
							// request need not re-declare the capability.
							// The response grants exactly this one call.
							execCtx = mcp.WithTasksExtension(mcp.WithInputResponses(ctx, map[string]json.RawMessage{
								mcp.ApprovalInputKey: pa.Response,
							}))
						} else {
							denied = true
						}
					}
				}
				// A gate for a different step id is stale (e.g. the
				// checkpoint moved); drop it and fail closed by letting
				// the gate re-trip if the tool still requires approval.
			}

			var r StepResult
			if denied {
				r = StepResult{Tool: step.Tool, ID: stepID, Success: false, Text: "approval denied"}
			} else {
				text, success, execErr := e.execute(execCtx, step.Tool, params)

				// MRTR: a task-tracked campaign whose step tripped the
				// operator-approval gate pauses (checkpointed, resumable)
				// instead of failing the step.
				var approvalReq *ApprovalRequiredError
				if errors.As(execErr, &approvalReq) {
					return e.pauseForApproval(state, allResults, i, step, stepID, approvalReq), nil
				}

				// Cancellation or timeout mid-step pauses rather than fails; the
				// interrupted step re-runs from its checkpoint on resume.
				if ctx.Err() != nil {
					return e.pause(ctx, state, allResults, i), ctx.Err()
				}

				r = StepResult{Tool: step.Tool, ID: stepID, Success: success, Text: text}
				if execErr != nil {
					r.Success = false
					r.Text = fmt.Sprintf("execution error: %s", execErr.Error())
				}
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
					failMsg := ""
					if denied {
						failMsg = "approval denied"
					}
					return e.fail(state, allResults, i, failMsg), nil
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

		// Cross-replica cancel: before overwriting the persisted state,
		// re-read it. Another process sharing the state dir may have marked
		// the campaign cancelled while this step ran (Cancel falls back to
		// persisting that marker when the run is not local to it). Stop
		// gracefully at this checkpoint instead of clobbering the marker.
		if e.persistedCancelled(state.WorkflowID) {
			state.Status = "cancelled"
			state.Error = "cancelled by another process"
			state.UpdatedAt = time.Now().Unix()
			if err := e.state.Save(state); err != nil {
				log.Printf("workflow: checkpoint save failed: %v", err)
			}
			return buildResult(state, allResults, false), nil
		}

		// Checkpoint every step.
		state.UpdatedAt = time.Now().Unix()
		if err := e.state.Save(state); err != nil {
			log.Printf("workflow: checkpoint save failed: %v", err)
		}
	}

	state.Status = "completed"
	state.UpdatedAt = time.Now().Unix()
	result := buildResult(state, allResults, true)
	// Persist the final WorkflowResult so tasks/get can serve the exact
	// campaign/run output after the run finishes.
	if data, err := json.Marshal(result); err == nil {
		state.FinalResult = data
	}
	if err := e.state.Save(state); err != nil {
		log.Printf("workflow: checkpoint save failed: %v", err)
	}
	return result, nil
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

// pauseForApproval checkpoints a task-tracked campaign whose step tripped
// the operator-approval gate (MRTR). The gated step re-runs on resume once
// the operator answers via tasks/update; the pending-approval record holds
// the elicitation identity so tasks/get can restate the request.
func (e *EnhancedEngine) pauseForApproval(state *State, allResults []StepResult, i int, step EnhancedStep, stepID string, req *ApprovalRequiredError) *WorkflowResult {
	message := req.Message
	if message == "" {
		message = fmt.Sprintf("Tool %q requires operator approval; approve or deny via tasks/update.", step.Tool)
	}
	requestID := req.RequestID
	if requestID == "" {
		requestID = GenerateID()
	}
	state.Status = "paused"
	state.Error = fmt.Sprintf("step %s awaits operator approval for tool %q", stepID, step.Tool)
	state.PendingApproval = &PendingApproval{
		Tool:      step.Tool,
		StepID:    stepID,
		RequestID: requestID,
		Message:   message,
	}
	state.NextIndex = i
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
	req, err := parseCampaignRequest(params)
	if err != nil {
		return nil, err
	}
	result, err := e.RunEnhanced(ctx, req)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal campaign result: %w", err)
	}
	return data, nil
}

// parseCampaignRequest strictly decodes campaign/run-shaped params: one
// JSON object, no unknown fields. The one exception is _meta: it is
// per-request protocol metadata (e.g. the clientCapabilities that negotiate
// the tasks extension), not campaign params, so it is stripped before the
// strict decode.
func parseCampaignRequest(params json.RawMessage) (*EnhancedWorkflowRequest, error) {
	var req EnhancedWorkflowRequest
	decoder := json.NewDecoder(bytes.NewReader(stripRequestMeta(params)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return nil, fmt.Errorf("invalid campaign params: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("campaign must contain exactly one JSON object")
	}
	return &req, nil
}

// stripRequestMeta removes the _meta key from a JSON object. Params that
// are not objects, or carry no _meta, are returned unchanged.
func stripRequestMeta(params json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(params, &obj); err != nil || obj == nil {
		return params
	}
	if _, ok := obj["_meta"]; !ok {
		return params
	}
	delete(obj, "_meta")
	data, err := json.Marshal(obj)
	if err != nil {
		return params
	}
	return data
}

// StartAsyncFromJSON is the JSON-RPC handler for campaign/start's async
// path: parse, durably persist the initial state, launch in the
// background, and return the task id (= workflow id). See StartAsync.
func (e *EnhancedEngine) StartAsyncFromJSON(ctx context.Context, params json.RawMessage) (string, bool, error) {
	req, err := parseCampaignRequest(params)
	if err != nil {
		return "", false, err
	}
	return e.StartAsync(ctx, req)
}

// TaskUpdateFromJSON is the JSON-RPC handler for tasks/update: it records
// the client's inputResponses on a paused campaign's pending approval
// request. Per the tasks extension, unknown task ids are errors and
// unknown or stale response keys are acknowledged and ignored.
func (e *EnhancedEngine) TaskUpdateFromJSON(params json.RawMessage) (json.RawMessage, error) {
	var req struct {
		TaskID         string                     `json:"taskId"`
		InputResponses map[string]json.RawMessage `json:"inputResponses"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid tasks/update params: %w", err)
	}
	if req.TaskID == "" {
		return nil, fmt.Errorf("taskId is required")
	}
	if err := ValidWorkflowID(req.TaskID); err != nil {
		return nil, fmt.Errorf("unknown taskId %q", req.TaskID)
	}

	ack := json.RawMessage(`{"accepted":true}`)

	response, ok := req.InputResponses[mcp.ApprovalInputKey]
	if !ok {
		// Unknown key: ack and ignore (spec).
		return ack, nil
	}
	// A campaign holds a pending approval only while paused (the run
	// goroutine has exited and released the run lock), so this
	// read-modify-write cannot interleave with checkpoint writes.
	state, err := e.state.Load(req.TaskID)
	if err != nil {
		return nil, fmt.Errorf("unknown taskId %q", req.TaskID)
	}
	pa := state.PendingApproval
	if pa == nil {
		// Stale: no approval is pending (running, terminal, or never
		// gated). Ack and ignore.
		return ack, nil
	}
	// When the response echoes a request id it must match the pending
	// elicitation; a mismatch is a stale answer to an earlier gate.
	var probe struct {
		RequestID string `json:"requestId"`
	}
	if err := json.Unmarshal(response, &probe); err == nil && probe.RequestID != "" && probe.RequestID != pa.RequestID {
		return ack, nil
	}

	pa.Response = response
	if mcp.IsAffirmativeApproval(response) {
		pa.Resolved = ApprovalDecisionApproved
	} else {
		// A response that is present but not affirmative is a denial
		// (fail closed).
		pa.Resolved = ApprovalDecisionDenied
	}
	state.UpdatedAt = time.Now().Unix()
	if err := e.state.Save(state); err != nil {
		return nil, fmt.Errorf("save task update: %w", err)
	}
	return ack, nil
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
