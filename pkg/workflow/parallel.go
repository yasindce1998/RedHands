package workflow

import (
	"context"
	"fmt"
	"sync"
)

// RunParallel executes multiple steps concurrently and collects results. It
// returns the ordered results and the number of failed steps.
func (e *EnhancedEngine) RunParallel(ctx context.Context, steps []EnhancedStep, results map[string]StepResult, allResults []StepResult) ([]StepResult, int) {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		outputs = make([]StepResult, len(steps))
		failed  int
	)

	sem := make(chan struct{}, e.maxParallel)

	for i, step := range steps {
		wg.Add(1)
		go func(idx int, s EnhancedStep) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				mu.Lock()
				outputs[idx] = StepResult{
					Tool:    s.Tool,
					Success: false,
					Text:    "cancelled",
				}
				failed++
				mu.Unlock()
				return
			default:
			}

			stepID := s.ID
			if stepID == "" {
				stepID = fmt.Sprintf("parallel_%d", idx)
			}

			params, err := substituteCampaignVars(s.Params, results, allResults)
			var text string
			var success bool
			if err != nil {
				text = fmt.Sprintf("execution error: %s", err.Error())
			} else {
				var execErr error
				text, success, execErr = e.execute(ctx, s.Tool, params)
				if execErr != nil {
					success = false
					text = fmt.Sprintf("execution error: %s", execErr.Error())
				}
			}

			r := StepResult{Tool: s.Tool, ID: stepID, Success: success, Text: text}

			mu.Lock()
			outputs[idx] = r
			if !success {
				failed++
			}
			results[stepID] = r
			mu.Unlock()
		}(i, step)
	}

	wg.Wait()

	return outputs, failed
}
