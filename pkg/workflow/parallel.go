package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

// parallelGate records one sub-step whose execution tripped the
// operator-approval gate: instead of failing the sub-step (the old
// conservative behavior), the whole group pauses once and the gate
// becomes one pending request in the pause record.
type parallelGate struct {
	// idx is the sub-step's position within the group.
	idx int
	// id is the sub-step's canonical id (parallelStepID).
	id string
	// step is the gated sub-step.
	step EnhancedStep
	// req carries the elicitation details issued for this gate.
	req *ApprovalRequiredError
}

// parallelOutcome is a parallel group's execution result.
type parallelOutcome struct {
	// results holds one entry per sub-step, in order. A sub-step that
	// tripped an approval gate has no entry this round (its outcome is
	// the gate, recorded in gates).
	results []StepResult
	// reused marks sub-steps whose results were replayed from the
	// checkpoint instead of executed (already completed, or a recorded
	// non-approval failure kept on resume). Reused results must not be
	// re-recorded.
	reused map[int]bool
	// failed counts failed sub-steps this round, including replayed
	// failures and denials, feeding the group's on_fail policy.
	failed int
	// gates lists the sub-steps that tripped approval gates this round.
	gates []*parallelGate
}

// groupReplay carries the resume state of a parallel group paused on
// approval gates: the per-gate operator decisions recorded via
// tasks/update, keyed by gated sub-step id. active is false for fresh
// executions (first run, goto re-run, or a pause that predates the group).
type groupReplay struct {
	active    bool
	decisions map[string]*PendingApprovalRequest
}

// RunParallel executes a parallel group's sub-steps concurrently and
// collects their results, gate trips, and failure count.
//
// MRTR replay: when replay is active (the group is resuming a run paused
// on approval gates), sub-steps that already completed during the paused
// partial run are not re-executed — their recorded result is reused;
// sub-steps that failed for non-approval reasons keep their recorded
// failure; approved sub-steps re-run with a one-call approval bypass
// carrying their own gate's response (never in the step params); denied
// sub-steps become failed sub-steps ("approval denied") that flow through
// the group's on_fail machinery; and unanswered gates re-trip with fresh
// request ids (fail closed). When replay is inactive every sub-step runs.
func (e *EnhancedEngine) RunParallel(ctx context.Context, parentID string, steps []EnhancedStep, state *State, allResults []StepResult, replay *groupReplay) *parallelOutcome {
	outcome := &parallelOutcome{
		results: make([]StepResult, len(steps)),
		reused:  make(map[int]bool),
	}
	if replay == nil {
		replay = &groupReplay{}
	}

	// Phase 1 (serial, before any goroutine starts, so no locking is
	// needed): decide per sub-step whether it runs, replays a recorded
	// result, replays a recorded failure, or is denied.
	type subPlan struct {
		run     bool
		reuseOK bool // replay a recorded success
		denied  bool
		bypass  json.RawMessage // per-gate approval response for the re-run
	}
	plans := make([]subPlan, len(steps))
	for i := range steps {
		subID := parallelStepID(steps, i, parentID)
		if !replay.active {
			plans[i].run = true
			continue
		}
		// Already completed during the paused partial run: reuse.
		if state.GroupCompleted[subID] {
			if r, ok := state.Results[subID]; ok && r.Success {
				outcome.results[i] = r
				outcome.reused[i] = true
				continue
			}
		}
		// A gate this sub-step tripped in the paused run: apply the
		// operator's recorded decision, if any.
		if dec, ok := replay.decisions[subID]; ok {
			if approved, responded := dec.Decision(); responded {
				if approved {
					plans[i].run = true
					plans[i].bypass = dec.Response
					continue
				}
				// Denied: the sub-step fails without executing.
				plans[i].denied = true
				continue
			}
			// Unanswered: fall through and re-run; the gate re-trips
			// with a fresh request id (fail closed).
		} else if r, ok := state.Results[subID]; ok && !r.Success {
			// Failed for non-approval reasons during the paused partial
			// run: keep the recorded failure.
			outcome.results[i] = r
			outcome.reused[i] = true
			outcome.failed++
			continue
		}
		plans[i].run = true
	}
	for i, plan := range plans {
		if plan.denied {
			subID := parallelStepID(steps, i, parentID)
			outcome.results[i] = StepResult{Tool: steps[i].Tool, ID: subID, Success: false, Text: "approval denied"}
			outcome.failed++
		}
	}

	// Phase 2: execute the planned sub-steps concurrently.
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	sem := make(chan struct{}, e.maxParallel)

	for i, s := range steps {
		if !plans[i].run {
			continue
		}
		idx, subID, bypass := i, parallelStepID(steps, i, parentID), plans[i].bypass
		wg.Add(1)
		go func() {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				mu.Lock()
				outcome.results[idx] = StepResult{
					Tool:    s.Tool,
					ID:      subID,
					Success: false,
					Text:    "cancelled",
				}
				outcome.failed++
				mu.Unlock()
				return
			default:
			}

			// state.Results and allResults are read-only while the group
			// runs (results are merged after the group finishes), so
			// substitution needs no lock.
			params, err := substituteCampaignVars(s.Params, state.Results, allResults)
			var text string
			var success bool
			var execErr error
			if err != nil {
				text = fmt.Sprintf("execution error: %s", err.Error())
			} else {
				execCtx := ctx
				if len(bypass) > 0 {
					// The approval was obtained through the tasks
					// protocol, so the re-run re-establishes the
					// tasks-extension marker on the execution context
					// itself. The response grants exactly this one call
					// and belongs to this sub-step's own gate.
					execCtx = mcp.WithTasksExtension(mcp.WithInputResponses(ctx, map[string]json.RawMessage{
						mcp.ApprovalInputKey: bypass,
					}))
				}
				text, success, execErr = e.execute(execCtx, s.Tool, params)
				var approvalReq *ApprovalRequiredError
				if errors.As(execErr, &approvalReq) {
					// MRTR: a gated sub-step pauses the group instead of
					// failing; the caller pauses the campaign once with
					// one pending request per gated sub-step.
					mu.Lock()
					outcome.gates = append(outcome.gates, &parallelGate{idx: idx, id: subID, step: s, req: approvalReq})
					mu.Unlock()
					return
				}
				if execErr != nil {
					success = false
					text = fmt.Sprintf("execution error: %s", execErr.Error())
				}
			}

			r := StepResult{Tool: s.Tool, ID: subID, Success: success, Text: text}
			mu.Lock()
			outcome.results[idx] = r
			if !success {
				outcome.failed++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	return outcome
}

// mergeGroupResults checkpoints a group's sub-step results into the
// campaign state: successes are recorded (recorder, MITRE aggregation,
// Results) and marked in the run-scoped completion set so a resume of a
// gate-paused group skips them; failures (including denials) are persisted
// under their canonical sub-step ids so a resumed group keeps them.
// Gated sub-steps have no result to merge. It returns the extended result
// list and the number of output bytes added.
func (e *EnhancedEngine) mergeGroupResults(state *State, step EnhancedStep, stepID string, outcome *parallelOutcome, allResults []StepResult) ([]StepResult, int) {
	gated := make(map[int]bool, len(outcome.gates))
	for _, g := range outcome.gates {
		gated[g.idx] = true
	}
	added := 0
	for idx, r := range outcome.results {
		if gated[idx] {
			continue
		}
		r.ID = parallelStepID(step.Parallel, idx, stepID)
		if r.Success && !outcome.reused[idx] {
			e.recordStep(state, step.Parallel[idx], r.ID, &r)
			state.aggregateMITRE(step.Parallel[idx])
		}
		if r.Success {
			if state.GroupCompleted == nil {
				state.GroupCompleted = make(map[string]bool)
			}
			state.GroupCompleted[r.ID] = true
		}
		state.Results[r.ID] = r
		allResults = append(allResults, r)
		added += len(r.Text)
	}
	return allResults, added
}
