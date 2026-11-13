package workflow

// Package workflow note: this package depends on pkg/mcp solely for the
// per-request context contract (tasks-extension capability marker and
// inputResponses) shared between the engine and the approval middleware.
// The dependency is one-directional: pkg/mcp never imports this package.
import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

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
	ID       string            `json:"id,omitempty"`
	Name     string            `json:"name,omitempty"`
	Steps    []EnhancedStep    `json:"steps"`
	Template string            `json:"template,omitempty"`
	Vars     map[string]string `json:"vars,omitempty"`
	// Engagement optionally binds the campaign to a named engagement. The
	// named engagement must exist and be the active engagement; every step's
	// targets are then scope-checked against it by the engagement middleware.
	Engagement string `json:"engagement,omitempty"`
}

// State represents a checkpoint of workflow execution.
type State struct {
	WorkflowID string `json:"workflow_id"`
	Name       string `json:"name,omitempty"`
	// Engagement records the engagement a campaign is bound to; it is
	// re-validated on resume.
	Engagement string                `json:"engagement,omitempty"`
	Steps      []EnhancedStep        `json:"steps"`
	Results    map[string]StepResult `json:"results"`
	NextIndex  int                   `json:"next_index"`
	Status     string                `json:"status"` // "running", "paused", "cancelled", "completed", "failed"
	Error      string                `json:"error,omitempty"`
	// JumpsUsed counts executed "goto:step_id" recovery jumps, persisted so
	// resumed campaigns keep their loop budget.
	JumpsUsed int `json:"jumps_used,omitempty"`
	// FinalResult persists the completed campaign's WorkflowResult (the
	// same JSON campaign/run returns) so tasks/get can serve it verbatim
	// after the run finishes. Populated only on completion.
	FinalResult json.RawMessage `json:"final_result,omitempty"`
	// PendingApproval records an operator-approval gate that paused a
	// task-tracked campaign (MRTR). The gated step re-runs on resume once
	// the operator's tasks/update response is recorded here.
	PendingApproval *PendingApproval `json:"pending_approval,omitempty"`
	// GroupCompleted records run-scoped, per-sub-step completion for a
	// parallel group paused on approval gates (MRTR): the canonical
	// sub-step IDs that already succeeded during the paused group's
	// partial execution. It is the source of truth for replay skipping on
	// resume and must never be confused with Results, which persists
	// campaign-wide: the completion set is cleared when the group
	// completes or re-runs (including via goto, which is a fresh
	// execution, not a resume). Sub-steps that failed for non-approval
	// reasons keep their recorded failure in Results instead.
	GroupCompleted map[string]bool `json:"group_completed,omitempty"`
	Techniques     []string        `json:"techniques,omitempty"`
	CreatedAt      int64           `json:"created_at,omitempty"`
	UpdatedAt      int64           `json:"updated_at,omitempty"`
}

// PendingApproval is the checkpoint record of an approval gate that paused
// a task-tracked campaign. It carries the elicitation identity (request
// id, message) the server issued and, once the operator answers via
// tasks/update, the consumed response.
type PendingApproval struct {
	// Tool is the gated step's tool name.
	Tool string `json:"tool"`
	// StepID is the gated step's id.
	StepID string `json:"step_id"`
	// RequestID identifies the elicitation request shown to the operator.
	RequestID string `json:"request_id"`
	// Message is the elicitation prompt.
	Message string `json:"message,omitempty"`
	// Response is the operator's inputResponses["approval"] payload.
	Response json.RawMessage `json:"response,omitempty"`
	// Resolved records the interpreted decision once answered:
	// "approved" or "denied". Consumed (cleared) when the gated step
	// re-runs on resume.
	Resolved string `json:"resolved,omitempty"`
	// Group marks a pause inside a parallel group: one or more sub-steps
	// of the StepID group tripped approval gates. The per-gate
	// elicitation records (and, once answered, per-gate responses) live
	// in Requests; tasks/get surfaces them as inputRequests keyed
	// "approval-<subStepID>" so the client can answer each sub-step
	// individually. The flat fields above stay empty for group pauses.
	Group bool `json:"group,omitempty"`
	// Requests lists the pending approval requests of a paused parallel
	// group, one entry per gated sub-step. Empty for sequential pauses,
	// which use the flat fields above.
	Requests []*PendingApprovalRequest `json:"requests,omitempty"`
}

// PendingApprovalRequest is one gated sub-step's elicitation inside a
// parallel group paused on approval gates (PendingApproval.Group). It
// mirrors the flat PendingApproval fields per sub-step.
type PendingApprovalRequest struct {
	// Tool is the gated sub-step's tool name.
	Tool string `json:"tool"`
	// StepID is the gated sub-step's canonical id.
	StepID string `json:"step_id"`
	// RequestID identifies the elicitation request shown to the operator.
	RequestID string `json:"request_id"`
	// Message is the elicitation prompt.
	Message string `json:"message,omitempty"`
	// Response is the operator's inputResponses["approval-<subStepID>"]
	// payload.
	Response json.RawMessage `json:"response,omitempty"`
	// Resolved records the interpreted decision once answered:
	// "approved" or "denied".
	Resolved string `json:"resolved,omitempty"`
}

// Decision interprets the recorded response, mirroring
// PendingApproval.Decision: responded reports whether an operator answer
// exists at all; when it does, approved reports whether it grants
// approval. A response that is present but not affirmative is a denial
// (fail closed).
func (r *PendingApprovalRequest) Decision() (approved, responded bool) {
	if r == nil || len(r.Response) == 0 {
		return false, false
	}
	return mcp.IsAffirmativeApproval(r.Response), true
}

// Approval decisions recorded on a PendingApproval.
const (
	ApprovalDecisionApproved = "approved"
	ApprovalDecisionDenied   = "denied"
)

// Decision interprets the recorded response. responded reports whether an
// operator answer exists at all; when it does, approved reports whether it
// grants approval. A response that is present but not affirmative is a
// denial (fail closed).
func (pa *PendingApproval) Decision() (approved, responded bool) {
	if pa == nil || len(pa.Response) == 0 {
		return false, false
	}
	return mcp.IsAffirmativeApproval(pa.Response), true
}

// ErrApprovalRequired is the sentinel wrapped by errors returned from a
// tool executor when a step's tool tripped the operator-approval gate and
// the campaign is task-tracked (the approval middleware returned an
// input_required result instead of a hard failure).
var ErrApprovalRequired = errors.New("tool requires operator approval")

// ApprovalRequiredError carries the elicitation details of an approval
// gate from the execution layer (which saw the input_required tool result)
// into the engine, which pauses the campaign with them.
type ApprovalRequiredError struct {
	// Tool is the gated tool's name.
	Tool string
	// RequestID is the elicitation request id issued for the gate.
	RequestID string
	// Message is the elicitation prompt issued for the gate.
	Message string
}

func (e *ApprovalRequiredError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("tool %q requires operator approval: %s", e.Tool, e.Message)
	}
	return fmt.Sprintf("tool %q requires operator approval", e.Tool)
}

// Unwrap makes errors.Is(err, ErrApprovalRequired) work through the
// executor's error path.
func (e *ApprovalRequiredError) Unwrap() error { return ErrApprovalRequired }

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
