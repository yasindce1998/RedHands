package workflow

import (
	"strconv"
	"strings"
)

// EvaluateCondition checks whether a condition is met given the current results.
func EvaluateCondition(cond *Condition, results map[string]StepResult) bool {
	return EvaluateConditionWithIndexed(cond, results, nil)
}

// EvaluateConditionWithIndexed resolves conditions against both named step
// results and the ordered result list. A condition's Step may be a step ID,
// "$prev" (or "prev"), or a zero-based decimal step index.
func EvaluateConditionWithIndexed(cond *Condition, named map[string]StepResult, indexed []StepResult) bool {
	if cond == nil {
		return true
	}

	r, ok := resolveConditionStep(cond.Step, named, indexed)
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
	case "json_exists":
		_, ok := lookupResultPath(r, cond.Path)
		return ok
	case "json_not_exists":
		_, ok := lookupResultPath(r, cond.Path)
		return !ok
	case "json_equals":
		v, ok := lookupResultPath(r, cond.Path)
		return ok && ValueToString(v) == cond.Value
	case "json_not_equals":
		v, ok := lookupResultPath(r, cond.Path)
		return ok && ValueToString(v) != cond.Value
	case "json_contains":
		v, ok := lookupResultPath(r, cond.Path)
		return ok && strings.Contains(ValueToString(v), cond.Value)
	case "json_gt":
		return compareJSONNumbers(r, cond.Path, cond.Value, func(got, want float64) bool { return got > want })
	case "json_lt":
		return compareJSONNumbers(r, cond.Path, cond.Value, func(got, want float64) bool { return got < want })
	default:
		return true
	}
}

func resolveConditionStep(ref string, named map[string]StepResult, indexed []StepResult) (StepResult, bool) {
	if ref == "" || ref == "$prev" || ref == "prev" {
		if len(indexed) == 0 {
			return StepResult{}, false
		}
		return indexed[len(indexed)-1], true
	}
	if r, ok := named[ref]; ok {
		return r, true
	}
	if idx, err := strconv.Atoi(ref); err == nil && idx >= 0 && idx < len(indexed) {
		return indexed[idx], true
	}
	return StepResult{}, false
}

func lookupResultPath(r StepResult, path string) (any, bool) {
	raw, ok := extractStructured(r)
	if !ok {
		return nil, false
	}
	if path == "" {
		return resultField(r, "json", "")
	}
	return lookupPath(raw, path)
}

func compareJSONNumbers(r StepResult, path, value string, cmp func(got, want float64) bool) bool {
	v, ok := lookupResultPath(r, path)
	if !ok {
		return false
	}
	got, err := strconv.ParseFloat(ValueToString(v), 64)
	if err != nil {
		return false
	}
	want, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}
	return cmp(got, want)
}
