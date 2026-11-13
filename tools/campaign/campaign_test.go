package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

// mockEngine is a recording fake for the Engine interface: every handler
// stores the exact params it received and returns a canned result.
type mockEngine struct {
	runParams       json.RawMessage
	statusParams    json.RawMessage
	listParams      json.RawMessage
	resumeParams    json.RawMessage
	cancelParams    json.RawMessage
	templatesParams json.RawMessage
	getParams       json.RawMessage
	saveParams      json.RawMessage

	runErr error
}

var (
	runResult       = json.RawMessage(`{"workflow_id":"wf-123","status":"completed","steps":[],"success":true}`)
	statusResult    = json.RawMessage(`{"workflow_id":"wf-123","status":"running","steps":[],"next_index":1}`)
	listResult      = json.RawMessage(`[{"workflow_id":"wf-123","status":"completed"},{"workflow_id":"wf-456","status":"paused"}]`)
	resumeResult    = json.RawMessage(`{"workflow_id":"wf-123","status":"completed","steps":[],"success":true}`)
	cancelResult    = json.RawMessage(`{"cancelled":true}`)
	templatesResult = json.RawMessage(`[{"name":"recon-sweep","description":"Full recon"},{"name":"ad-chain","description":"AD abuse"}]`)
	getResult       = json.RawMessage(`{"name":"recon-sweep","description":"Full recon","vars":[],"steps":[{"tool":"nmap_port_scan"}]}`)
	saveResult      = json.RawMessage(`{"saved":true}`)
)

func (m *mockEngine) RunFromJSON(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
	m.runParams = params
	if m.runErr != nil {
		return nil, m.runErr
	}
	return runResult, nil
}

func (m *mockEngine) StatusFromJSON(params json.RawMessage) (json.RawMessage, error) {
	m.statusParams = params
	return statusResult, nil
}

func (m *mockEngine) ListFromJSON(params json.RawMessage) (json.RawMessage, error) {
	m.listParams = params
	return listResult, nil
}

func (m *mockEngine) ResumeFromJSON(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
	m.resumeParams = params
	return resumeResult, nil
}

func (m *mockEngine) CancelFromJSON(params json.RawMessage) (json.RawMessage, error) {
	m.cancelParams = params
	return cancelResult, nil
}

func (m *mockEngine) TemplatesFromJSON(params json.RawMessage) (json.RawMessage, error) {
	m.templatesParams = params
	return templatesResult, nil
}

func (m *mockEngine) GetTemplateFromJSON(params json.RawMessage) (json.RawMessage, error) {
	m.getParams = params
	return getResult, nil
}

func (m *mockEngine) SaveTemplateFromJSON(params json.RawMessage) (json.RawMessage, error) {
	m.saveParams = params
	return saveResult, nil
}

// Compile-time check: the real engine satisfies the local interface.
var _ Engine = (*workflow.EnhancedEngine)(nil)

func allTools(engine Engine) []interface {
	Name() string
	Description() string
	InputSchema() json.RawMessage
	Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error)
} {
	return []interface {
		Name() string
		Description() string
		InputSchema() json.RawMessage
		Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error)
	}{
		NewStart(engine), NewStatus(engine), NewList(engine), NewResume(engine),
		NewCancel(engine), NewTemplates(engine), NewTemplateGet(engine), NewTemplateSave(engine),
	}
}

var toolNames = map[string]bool{
	"campaign_start": true, "campaign_status": true, "campaign_list": true,
	"campaign_resume": true, "campaign_cancel": true, "campaign_templates": true,
	"campaign_template_get": true, "campaign_template_save": true,
}

// readOnlyTools must not claim side effects in their descriptions.
var readOnlyTools = map[string]bool{
	"campaign_status": true, "campaign_list": true,
	"campaign_templates": true, "campaign_template_get": true,
}

func call(t *testing.T, tool interface {
	Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error)
}, params string) *mcp.ToolResult {
	t.Helper()
	var raw json.RawMessage
	if params != "" {
		raw = json.RawMessage(params)
	}
	result, err := tool.Execute(context.Background(), raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return result
}

func TestAllToolNamesAndSchemas(t *testing.T) {
	engine := &mockEngine{}
	tools := allTools(engine)
	if len(tools) != 8 {
		t.Fatalf("expected 8 campaign tools, got %d", len(tools))
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		name := tool.Name()
		if !toolNames[name] {
			t.Errorf("unexpected tool name %q", name)
		}
		if seen[name] {
			t.Errorf("duplicate tool name %q", name)
		}
		seen[name] = true

		if strings.TrimSpace(tool.Description()) == "" {
			t.Errorf("tool %s: empty description", name)
		}

		// Schema must be a valid 2020-12 style object schema.
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema(), &schema); err != nil {
			t.Errorf("tool %s: invalid schema JSON: %v", name, err)
			continue
		}
		if schema["type"] != "object" {
			t.Errorf("tool %s: schema type must be \"object\", got %v", name, schema["type"])
		}
		if _, ok := schema["properties"]; !ok {
			t.Errorf("tool %s: schema missing properties", name)
		}
		if req, ok := schema["required"]; ok {
			if _, ok := req.([]any); !ok {
				t.Errorf("tool %s: required must be an array", name)
			}
		}
		if req, ok := schema["required"].([]any); ok {
			for _, field := range req {
				f, _ := field.(string)
				props, _ := schema["properties"].(map[string]any)
				if f != "" && props[f] == nil {
					t.Errorf("tool %s: required field %q missing from properties", name, f)
				}
			}
		}
	}
	for name := range toolNames {
		if !seen[name] {
			t.Errorf("missing tool %q", name)
		}
	}
}

func TestReadOnlyDescriptionsNoSideEffects(t *testing.T) {
	for _, tool := range allTools(&mockEngine{}) {
		name := tool.Name()
		desc := strings.ToLower(tool.Description())
		if !readOnlyTools[name] {
			continue
		}
		if !strings.Contains(desc, "read-only") {
			t.Errorf("tool %s: read-only tool description should say read-only", name)
		}
		for _, phrase := range []string{"destructive", "executes real tools", "this executes the tools"} {
			if strings.Contains(desc, phrase) {
				t.Errorf("tool %s: read-only description claims side effects (%q)", name, phrase)
			}
		}
	}
}

func TestStartDelegatesPassthroughAndFirstLine(t *testing.T) {
	engine := &mockEngine{}
	tool := NewStart(engine)

	params := `{"id":"wf-123","name":"demo","steps":[{"tool":"nmap_port_scan","params":{"target":"192.0.2.0/24"}}],"engagement":"lab"}`
	result := call(t, tool, params)
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}

	// Delegation must pass the exact JSON through.
	if string(engine.runParams) != params {
		t.Fatalf("RunFromJSON params = %s, want %s", engine.runParams, params)
	}

	// The workflow_id must be in the FIRST line: "Campaign <id> — <status>."
	text := result.Content[0].Text
	firstLine := text[:strings.IndexByte(text, '\n')]
	if firstLine != "Campaign wf-123 — completed." {
		t.Fatalf("first line = %q, want %q", firstLine, "Campaign wf-123 — completed.")
	}
	// Result wraps the raw engine JSON in a fenced block plus guidance.
	if !strings.Contains(text, "```json\n"+string(runResult)+"\n```") {
		t.Fatalf("result missing fenced engine JSON:\n%s", text)
	}
	if !strings.Contains(text, "campaign_status") {
		t.Fatalf("result should point at campaign_status for polling:\n%s", text)
	}
}

func TestStartEngineErrorAndLocalIDValidation(t *testing.T) {
	engine := &mockEngine{runErr: fmt.Errorf("invalid campaign params: unknown field \"staps\"")}
	tool := NewStart(engine)

	result := call(t, tool, `{"staps":[]}`)
	if !result.IsError {
		t.Fatalf("expected error result for engine failure")
	}
	if !strings.Contains(result.Content[0].Text, "campaign failed to start") {
		t.Fatalf("error text should wrap engine error: %s", result.Content[0].Text)
	}

	// Malformed custom ids are rejected locally, before the engine runs.
	for _, bad := range []string{`{"id":"bad id!","steps":[]}`, `{"id":"` + strings.Repeat("x", 65) + `","steps":[]}`, `{"id":"../escape","steps":[]}`} {
		engine.runParams = nil
		result := call(t, tool, bad)
		if !result.IsError {
			t.Fatalf("expected error result for params %s", bad)
		}
		if !strings.Contains(result.Content[0].Text, "id must be") {
			t.Fatalf("error text should explain the id rule: %s", result.Content[0].Text)
		}
		if engine.runParams != nil {
			t.Fatalf("engine must not be called for invalid id (params %s)", bad)
		}
	}
}

func TestWorkflowIDToolsDelegateAndValidate(t *testing.T) {
	engine := &mockEngine{}
	params := `{"workflow_id":"wf-123"}`

	cases := []struct {
		name string
		tool interface {
			Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error)
		}
		record *json.RawMessage
		needle string
	}{
		{"status", NewStatus(engine), &engine.statusParams, "Campaign wf-123 is running."},
		{"resume", NewResume(engine), &engine.resumeParams, "Campaign wf-123 resumed — completed."},
		{"cancel", NewCancel(engine), &engine.cancelParams, "Campaign wf-123 cancelled."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := call(t, tc.tool, params)
			if result.IsError {
				t.Fatalf("unexpected error result: %s", result.Content[0].Text)
			}
			if string(*tc.record) != params {
				t.Fatalf("engine params = %s, want %s", *tc.record, params)
			}
			if !strings.Contains(result.Content[0].Text, tc.needle) {
				t.Fatalf("result missing %q:\n%s", tc.needle, result.Content[0].Text)
			}
			if !strings.Contains(result.Content[0].Text, "```json") {
				t.Fatalf("result missing JSON fence:\n%s", result.Content[0].Text)
			}
		})
	}
}

func TestWorkflowIDValidation(t *testing.T) {
	engine := &mockEngine{}
	tools := []interface {
		Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error)
	}{
		NewStatus(engine), NewResume(engine), NewCancel(engine),
	}
	for _, tool := range tools {
		for _, tc := range []struct {
			name   string
			params string
			want   string
		}{
			{"missing workflow_id", `{}`, "workflow_id is required"},
			{"empty params", "", "params must be a JSON object"},
			{"not an object", `["wf-123"]`, "params must be a JSON object"},
			{"bad chars", `{"workflow_id":"wf 123!"}`, "invalid"},
			{"too long", `{"workflow_id":"` + strings.Repeat("a", 65) + `"}`, "invalid"},
			{"path escape", `{"workflow_id":"../../etc"}`, "invalid"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				result := call(t, tool, tc.params)
				if !result.IsError {
					t.Fatalf("expected error result for %s", tc.params)
				}
				if !strings.Contains(result.Content[0].Text, tc.want) {
					t.Fatalf("error %q missing %q", result.Content[0].Text, tc.want)
				}
			})
		}
	}
	// The engine must never be reached with invalid params.
	if engine.statusParams != nil || engine.resumeParams != nil || engine.cancelParams != nil {
		t.Fatal("engine was called with invalid workflow_id params")
	}
}

func TestListAndTemplatesNoParams(t *testing.T) {
	engine := &mockEngine{}

	result := call(t, NewList(engine), "")
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	if string(engine.listParams) != "{}" {
		t.Fatalf("ListFromJSON params = %s, want {}", engine.listParams)
	}
	if !strings.Contains(result.Content[0].Text, "2 campaign(s) tracked.") {
		t.Fatalf("result missing summary:\n%s", result.Content[0].Text)
	}

	result = call(t, NewTemplates(engine), `{}`)
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	if string(engine.templatesParams) != "{}" {
		t.Fatalf("TemplatesFromJSON params = %s, want {}", engine.templatesParams)
	}
	if !strings.Contains(result.Content[0].Text, "2 playbook template(s) available.") {
		t.Fatalf("result missing summary:\n%s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "campaign_template_get") {
		t.Fatalf("result should point at campaign_template_get:\n%s", result.Content[0].Text)
	}
}

func TestTemplateGetDelegatesAndValidates(t *testing.T) {
	engine := &mockEngine{}
	tool := NewTemplateGet(engine)

	result := call(t, tool, `{"name":"recon-sweep"}`)
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	if string(engine.getParams) != `{"name":"recon-sweep"}` {
		t.Fatalf("GetTemplateFromJSON params = %s", engine.getParams)
	}
	if !strings.Contains(result.Content[0].Text, `Playbook template "recon-sweep":`) {
		t.Fatalf("result missing summary:\n%s", result.Content[0].Text)
	}

	for _, tc := range []struct {
		name   string
		params string
		want   string
	}{
		{"missing name", `{}`, "name is required"},
		{"empty params", "", "params must be a JSON object"},
		{"bad name", `{"name":"bad name!"}`, "invalid"},
		{"path escape", `{"name":"../secrets"}`, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := call(t, tool, tc.params)
			if !result.IsError {
				t.Fatalf("expected error result for %s", tc.params)
			}
			if !strings.Contains(result.Content[0].Text, tc.want) {
				t.Fatalf("error %q missing %q", result.Content[0].Text, tc.want)
			}
		})
	}
}

func TestTemplateSaveDelegatesPassthrough(t *testing.T) {
	engine := &mockEngine{}
	tool := NewTemplateSave(engine)

	params := `{"name":"recon-sweep","description":"Full recon","vars":[{"name":"cidr","required":true}],"steps":[{"tool":"nmap_port_scan","params":{"target":"$cidr"}}]}`
	result := call(t, tool, params)
	if result.IsError {
		t.Fatalf("unexpected error result: %s", result.Content[0].Text)
	}
	// Passthrough: the engine (DisallowUnknownFields) validates strictly.
	if string(engine.saveParams) != params {
		t.Fatalf("SaveTemplateFromJSON params = %s, want %s", engine.saveParams, params)
	}
	if !strings.Contains(result.Content[0].Text, `Playbook template "recon-sweep" saved.`) {
		t.Fatalf("result missing summary:\n%s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "```json\n"+string(saveResult)+"\n```") {
		t.Fatalf("result missing fenced engine JSON:\n%s", result.Content[0].Text)
	}

	// The name is validated locally before the engine is called.
	engine.saveParams = nil
	for _, bad := range []string{`{"steps":[]}`, `{"name":"","steps":[]}`, `{"name":"bad name","steps":[]}`} {
		result := call(t, tool, bad)
		if !result.IsError {
			t.Fatalf("expected error result for %s", bad)
		}
		if engine.saveParams != nil {
			t.Fatalf("engine must not be called for invalid name (params %s)", bad)
		}
	}
}

func TestNonObjectParamsRejected(t *testing.T) {
	engine := &mockEngine{}
	tools := []interface {
		Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error)
	}{
		NewStart(engine), NewStatus(engine), NewResume(engine), NewCancel(engine),
		NewTemplateGet(engine), NewTemplateSave(engine),
	}
	for _, tool := range tools {
		for _, params := range []string{`"string"`, `[1,2]`, `42`} {
			result := call(t, tool, params)
			if !result.IsError {
				t.Fatalf("%s: expected error result for params %s", tool.(interface{ Name() string }).Name(), params)
			}
		}
	}
}

func TestStartDescriptionDocumentsDestructiveness(t *testing.T) {
	desc := NewStart(&mockEngine{}).Description()
	if !strings.Contains(desc, "DESTRUCTIVE") {
		t.Error("campaign_start description should be annotated as destructive")
	}
	for _, want := range []string{"steps", "template", "condition", "on_fail", "parallel", "record", "mitre", "engagement", "campaign_status"} {
		if !strings.Contains(strings.ToLower(desc), strings.ToLower(want)) {
			t.Errorf("campaign_start description missing %q", want)
		}
	}
}
