package workflow

import (
	"fmt"
	"regexp"
)

// StepRecorder persists structured items extracted from campaign step output
// (hosts, services, credentials, findings). Implementations are provided by
// the application layer; the engine stays decoupled from any storage.
type StepRecorder interface {
	// RecordStep stores the items selected by one record rule. Items are
	// decoded JSON values (objects). stepMITRE carries the step's ATT&CK
	// tags for enrichment. Returning an error records a warning; it does
	// not fail the campaign.
	RecordStep(workflowID, stepID, tool string, rule RecordRule, items []any, stepMITRE []string) error
}

// recordRuleTypes lists the entry types a record rule may produce.
var recordRuleTypes = map[string]bool{
	"host": true, "service": true, "credential": true, "finding": true,
}

// mitreIDRe matches ATT&CK technique and sub-technique IDs (T1613, T1552.007).
var mitreIDRe = regexp.MustCompile(`^[Tt]\d{4}(\.\d{3})?$`)

// ValidMITREID reports whether s is a well-formed ATT&CK technique ID.
func ValidMITREID(s string) bool {
	return mitreIDRe.MatchString(s)
}

// normalizeMITREID upper-cases a technique ID ("t1613" -> "T1613").
func normalizeMITREID(s string) string {
	if len(s) > 0 && s[0] == 't' {
		return "T" + s[1:]
	}
	return s
}

// validateRecordRule enforces rule shape before execution.
func validateRecordRule(rule RecordRule) error {
	if !recordRuleTypes[rule.Type] {
		return fmt.Errorf("record rule type must be host, service, credential, or finding (got %q)", rule.Type)
	}
	if rule.Path == "" {
		return fmt.Errorf("record rule for %s needs a path", rule.Type)
	}
	if len(rule.Fields) == 0 {
		return fmt.Errorf("record rule for %s needs at least one field mapping", rule.Type)
	}
	return nil
}

// recordStep applies a step's record rules against its structured output.
// Failures are reported per rule; they never abort the campaign.
func (e *EnhancedEngine) recordStep(state *State, step EnhancedStep, stepID string, r *StepResult) {
	if e.recorder == nil || len(step.Record) == 0 || r == nil || !r.Success || r.Skipped {
		return
	}
	raw, ok := extractStructured(*r)
	if !ok {
		r.Text += "\n\n(recording skipped: step output is not structured JSON)"
		return
	}
	recorded := 0
	for _, rule := range step.Record {
		value, ok := lookupPath(raw, rule.Path)
		if !ok {
			r.Text += fmt.Sprintf("\n\n(recording warning: path %q not found)", rule.Path)
			continue
		}
		items, ok := value.([]any)
		if !ok {
			r.Text += fmt.Sprintf("\n\n(recording warning: path %q is not an array)", rule.Path)
			continue
		}
		if len(items) == 0 {
			continue
		}
		if err := e.recorder.RecordStep(state.WorkflowID, stepID, step.Tool, rule, items, step.MITRE); err != nil {
			r.Text += fmt.Sprintf("\n\n(recording warning: %s %q: %v)", rule.Type, rule.Path, err)
			continue
		}
		recorded += len(items)
	}
	if recorded > 0 {
		r.Recorded = recorded
	}
}

// aggregateMITRE adds a step's technique IDs to the campaign state.
func (state *State) aggregateMITRE(step EnhancedStep) {
	for _, id := range step.MITRE {
		id = normalizeMITREID(id)
		duplicate := false
		for _, existing := range state.Techniques {
			if existing == id {
				duplicate = true
				break
			}
		}
		if !duplicate {
			state.Techniques = append(state.Techniques, id)
		}
	}
}
