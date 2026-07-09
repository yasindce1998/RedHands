package workflow

import "strings"

// EvaluateCondition checks whether a condition is met given the current results.
func EvaluateCondition(cond *Condition, results map[string]StepResult) bool {
	if cond == nil {
		return true
	}

	r, ok := results[cond.Step]
	if !ok {
		return false
	}

	switch cond.Op {
	case "success":
		return r.Success
	case "failure":
		return !r.Success
	case "contains":
		return strings.Contains(r.Text, cond.Value)
	case "not_contains":
		return !strings.Contains(r.Text, cond.Value)
	case "equals":
		return r.Text == cond.Value
	case "not_equals":
		return r.Text != cond.Value
	default:
		return true
	}
}
