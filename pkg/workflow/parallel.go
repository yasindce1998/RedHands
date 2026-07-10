package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// RunParallel executes multiple steps concurrently and collects results.
func (e *EnhancedEngine) RunParallel(ctx context.Context, steps []EnhancedStep, results map[string]StepResult, allResults []StepResult) ([]StepResult, error) {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		outputs = make([]StepResult, len(steps))
		errs    []error
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
				mu.Unlock()
				return
			default:
			}

			stepID := s.ID
			if stepID == "" {
				stepID = fmt.Sprintf("parallel_%d", idx)
			}

			params := substituteVarsFromMap(s.Params, results, allResults)
			text, success, err := e.execute(ctx, s.Tool, params)

			r := StepResult{Tool: s.Tool, Success: success, Text: text}
			if err != nil {
				r.Success = false
				r.Text = fmt.Sprintf("execution error: %s", err.Error())
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}

			mu.Lock()
			outputs[idx] = r
			results[stepID] = r
			mu.Unlock()
		}(i, step)
	}

	wg.Wait()

	return outputs, nil
}

// substituteVarsFromMap replaces variables using a map of named results.
func substituteVarsFromMap(params json.RawMessage, named map[string]StepResult, indexed []StepResult) json.RawMessage {
	s := string(params)

	// Replace $prev.text
	if len(indexed) > 0 {
		prev := indexed[len(indexed)-1]
		s = replaceAll(s, "$prev.text", escapeJSON(prev.Text))
	}

	// Replace $step[N].text
	for i, r := range indexed {
		placeholder := fmt.Sprintf("$step[%d].text", i)
		s = replaceAll(s, placeholder, escapeJSON(r.Text))
	}

	// Replace ${step_id.text}
	for id, r := range named {
		placeholder := fmt.Sprintf("${%s.text}", id)
		s = replaceAll(s, placeholder, escapeJSON(r.Text))
	}

	return json.RawMessage(s)
}

func replaceAll(s, old, new string) string {
	for {
		idx := indexOf(s, old)
		if idx == -1 {
			return s
		}
		s = s[:idx] + new + s[idx+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
