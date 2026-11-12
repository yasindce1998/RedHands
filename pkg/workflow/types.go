package workflow

import "encoding/json"

// EnhancedStep extends Step with parallel execution, conditions, failure handling,
// structured recording, and MITRE ATT&CK tagging.
type EnhancedStep struct {
	ID        string          `json:"id,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Parallel  []EnhancedStep  `json:"parallel,omitempty"`
	Condition *Condition      `json:"condition,omitempty"`
	OnFail    string          `json:"on_fail,omitempty"`
	// Record extracts structured items from this step's output into the
	// target database (hosts, services, credentials, findings).
	Record []RecordRule `json:"record,omitempty"`
	// MITRE lists ATT&CK technique IDs implemented by this step
	// (e.g. ["T1613", "T1552.007"]).
	MITRE []string `json:"mitre,omitempty"`
}

// RecordRule maps a JSON array in a step result into target database entries.
type RecordRule struct {
	// Type of entry: "host", "service", "credential", or "finding".
	Type string `json:"type"`
	// Path is a dot-separated JSON path to an array of objects
	// (e.g. "hosts" or "results.findings").
	Path string `json:"path"`
	// Fields maps a target database field name to a relative JSON path
	// within each array element (e.g. {"ip": "ip", "hostname": "name"}).
	Fields map[string]string `json:"fields"`
}

// Condition determines whether a step should execute.
type Condition struct {
	// Check a previous step's result: a step ID, "$prev" for the immediately
	// preceding step, or a zero-based step index as a decimal string.
	Step string `json:"step,omitempty"`
	// Operator: "contains", "not_contains", "equals", "not_equals", "success",
	// "failure", "json_exists", "json_not_exists", "json_equals",
	// "json_not_equals", "json_contains", "json_gt", "json_lt"
	Op string `json:"op"`
	// Value compared by comparison operators.
	Value string `json:"value,omitempty"`
	// Path is a dot-separated JSON path ("hosts.0.ip") used by json_* operators.
	Path string `json:"path,omitempty"`
}

// EnhancedWorkflowRequest supports the full feature set.
type EnhancedWorkflowRequest struct {
	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name,omitempty"`
	Steps    []EnhancedStep `json:"steps"`
	Template string         `json:"template,omitempty"`
	Vars     map[string]string `json:"vars,omitempty"`
	// Engagement optionally binds the campaign to a named engagement. The
	// named engagement must exist and be the active engagement; every step's
	// targets are then scope-checked against it by the engagement middleware.
	Engagement string `json:"engagement,omitempty"`
}

// State represents a checkpoint of workflow execution.
type State struct {
	WorkflowID string                  `json:"workflow_id"`
	Name       string                  `json:"name,omitempty"`
	// Engagement records the engagement a campaign is bound to; it is
	// re-validated on resume.
	Engagement string                  `json:"engagement,omitempty"`
	Steps      []EnhancedStep          `json:"steps"`
	Results    map[string]StepResult   `json:"results"`
	NextIndex  int                     `json:"next_index"`
	Status     string                  `json:"status"` // "running", "paused", "cancelled", "completed", "failed"
	Error      string                  `json:"error,omitempty"`
	// JumpsUsed counts executed "goto:step_id" recovery jumps, persisted so
	// resumed campaigns keep their loop budget.
	JumpsUsed int      `json:"jumps_used,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
	CreatedAt int64    `json:"created_at,omitempty"`
	UpdatedAt int64    `json:"updated_at,omitempty"`
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
