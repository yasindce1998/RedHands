package workflow

import "encoding/json"

// EnhancedStep extends Step with parallel execution, conditions, and failure handling.
type EnhancedStep struct {
	ID        string          `json:"id,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Parallel  []EnhancedStep  `json:"parallel,omitempty"`
	Condition *Condition      `json:"condition,omitempty"`
	OnFail    string          `json:"on_fail,omitempty"`
}

// Condition determines whether a step should execute.
type Condition struct {
	// Check a previous step's result
	Step string `json:"step,omitempty"`
	// Operator: "contains", "not_contains", "equals", "not_equals", "success", "failure"
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
}

// EnhancedWorkflowRequest supports the full feature set.
type EnhancedWorkflowRequest struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name,omitempty"`
	Steps    []EnhancedStep `json:"steps"`
	Template string         `json:"template,omitempty"`
	Vars     map[string]string `json:"vars,omitempty"`
}

// State represents a checkpoint of workflow execution.
type State struct {
	WorkflowID string                  `json:"workflow_id"`
	Name       string                  `json:"name,omitempty"`
	Steps      []EnhancedStep          `json:"steps"`
	Results    map[string]StepResult   `json:"results"`
	NextIndex  int                     `json:"next_index"`
	Status     string                  `json:"status"` // "running", "paused", "completed", "failed"
	Error      string                  `json:"error,omitempty"`
}

// Template is a reusable workflow definition with variable placeholders.
type Template struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Vars        []TemplateVar  `json:"vars"`
	Steps       []EnhancedStep `json:"steps"`
}

// TemplateVar defines a variable expected by a template.
type TemplateVar struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Default     string `json:"default,omitempty"`
	Required    bool   `json:"required"`
}

// ScheduleEntry represents a scheduled workflow execution.
type ScheduleEntry struct {
	ID       string                  `json:"id"`
	Cron     string                  `json:"cron"`
	Workflow EnhancedWorkflowRequest `json:"workflow"`
	Enabled  bool                    `json:"enabled"`
	LastRun  int64                   `json:"last_run,omitempty"`
	NextRun  int64                   `json:"next_run,omitempty"`
}
