package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestEngine creates an EnhancedEngine with temp state/template dirs.
func newTestEngine(t *testing.T, exec ToolExecutor) (*EnhancedEngine, string) {
	t.Helper()
	dir := t.TempDir()
	return NewEnhancedEngine(exec, filepath.Join(dir, "state"), filepath.Join(dir, "templates"), 4), dir
}

func TestCampaignSequentialRun(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		mu.Lock()
		calls = append(calls, tool)
		mu.Unlock()
		return "ok", true, nil
	}
	engine, _ := newTestEngine(t, exec)

	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Name: "sequential",
		Steps: []EnhancedStep{
			{ID: "a", Tool: "tool_a"},
			{ID: "b", Tool: "tool_b"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success || result.Status != "completed" {
		t.Fatalf("expected completed campaign, got %+v", result)
	}
	if result.WorkflowID == "" {
		t.Fatal("expected workflow_id in result")
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %v", calls)
	}
}

func TestCampaignJSONDataflow(t *testing.T) {
	var captured json.RawMessage
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		switch tool {
		case "discover":
			// RedHands tools emit markdown with fenced JSON.
			return "## Discovery\n```json\n{\"hosts\":[{\"ip\":\"10.0.0.1\",\"ports\":[80,443]},{\"ip\":\"10.0.0.2\",\"ports\":[22]}],\"count\":2}\n```", true, nil
		case "capture":
			captured = params
			return "done", true, nil
		}
		return "", false, fmt.Errorf("unexpected tool %s", tool)
	}
	engine, _ := newTestEngine(t, exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{ID: "discover", Tool: "discover"},
			{ID: "capture", Tool: "capture", Params: json.RawMessage(
				`{"target":"$prev.json.hosts.0.ip","second":"$prev.json.hosts.1.ip","all":"$prev.json.hosts","count":"$prev.json.count","label":"host at $prev.json.hosts.0.ip","stale":"$prev.json.missing.path"}`)},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var p struct {
		Target string          `json:"target"`
		Second string          `json:"second"`
		All    json.RawMessage `json:"all"`
		Count  json.Number     `json:"count"`
		Label  string          `json:"label"`
		Stale  string          `json:"stale"`
	}
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("captured params invalid: %v (%s)", err, captured)
	}
	if p.Target != "10.0.0.1" || p.Second != "10.0.0.2" {
		t.Errorf("path extraction failed: target=%q second=%q", p.Target, p.Second)
	}
	// Whole-string placeholder over an array substitutes natively.
	if strings.TrimSpace(string(p.All)) != `[{"ip":"10.0.0.1","ports":[80,443]},{"ip":"10.0.0.2","ports":[22]}]` {
		t.Errorf("native array substitution failed: %s", p.All)
	}
	// Numeric JSON value keeps its type.
	if p.Count.String() != "2" {
		t.Errorf("numeric substitution failed: %s", p.Count.String())
	}
	if p.Label != "host at 10.0.0.1" {
		t.Errorf("embedded substitution failed: %q", p.Label)
	}
	// Unresolvable placeholders pass through untouched.
	if p.Stale != "$prev.json.missing.path" {
		t.Errorf("unresolved placeholder should pass through, got %q", p.Stale)
	}
}

func TestCampaignStepReferences(t *testing.T) {
	var captured json.RawMessage
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		switch tool {
		case "one":
			return `{"value":"alpha","n":5}`, true, nil
		case "two":
			return `{"value":"beta"}`, true, nil
		case "final":
			captured = params
			return "done", true, nil
		}
		return "", false, fmt.Errorf("unexpected tool %s", tool)
	}
	engine, _ := newTestEngine(t, exec)

	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{ID: "first", Tool: "one"},
			{ID: "second", Tool: "two"},
			{ID: "final", Tool: "final", Params: json.RawMessage(
				`{"a":"${first.json.value}","b":"$step[1].json.value","c":"$step[0].json.value","d":"${second.text}"}`)},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var p map[string]string
	if err := json.Unmarshal(captured, &p); err != nil {
		t.Fatalf("captured params invalid: %v", err)
	}
	if p["a"] != "alpha" || p["b"] != "beta" || p["c"] != "alpha" || p["d"] != `{"value":"beta"}` {
		t.Errorf("step reference substitution failed: %v", p)
	}
}

func TestCampaignConditions(t *testing.T) {
	var calls []string
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		calls = append(calls, tool)
		switch tool {
		case "scan":
			return "```json\n{\"findings\":3,\"open_ports\":[80,443]}\n```", true, nil
		case "exploit":
			return "exploited", true, nil
		case "skipme":
			return "should not run", true, nil
		}
		return "", false, fmt.Errorf("unexpected tool %s", tool)
	}
	engine, _ := newTestEngine(t, exec)

	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{ID: "scan", Tool: "scan"},
			{ID: "exploit", Tool: "exploit", Condition: &Condition{Step: "$prev", Op: "json_gt", Path: "findings", Value: "2"}},
			{ID: "skipme", Tool: "skipme", Condition: &Condition{Step: "$prev", Op: "json_equals", Path: "findings", Value: "99"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("campaign failed: %+v", result)
	}
	joined := strings.Join(calls, ",")
	if joined != "scan,exploit" {
		t.Fatalf("expected scan,exploit got %s", joined)
	}
	if !result.Steps[2].Skipped {
		t.Errorf("expected step 2 to be skipped: %+v", result.Steps[2])
	}
}

func TestCampaignOnFailContinueAndStop(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		if tool == "boom" {
			return "failure detail", false, nil
		}
		return "ok", true, nil
	}

	engine, _ := newTestEngine(t, exec)
	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{Tool: "boom", OnFail: "continue"},
			{Tool: "after"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success || len(result.Steps) != 2 {
		t.Fatalf("on_fail=continue should keep going: %+v", result)
	}

	engine2, _ := newTestEngine(t, exec)
	result2, err := engine2.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{Tool: "boom"},
			{Tool: "never"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Success || result2.Status != "failed" {
		t.Fatalf("default on_fail should stop: %+v", result2)
	}
	if len(result2.Steps) != 1 {
		t.Fatalf("failed campaign should not run later steps: %+v", result2)
	}
}

func TestCampaignGotoRecovery(t *testing.T) {
	attempts := 0
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		switch tool {
		case "flaky":
			attempts++
			if attempts < 3 {
				return "transient failure", false, nil
			}
			return "recovered", true, nil
		case "finish":
			return "done", true, nil
		}
		return "", false, fmt.Errorf("unexpected tool %s", tool)
	}
	engine, _ := newTestEngine(t, exec)

	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{ID: "start", Tool: "flaky", OnFail: "goto:start"},
			{ID: "finish", Tool: "finish"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("goto recovery should eventually succeed: %+v", result)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}

	// A goto loop that never recovers must hit the jump budget.
	endless := 0
	execEndless := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		endless++
		return "nope", false, nil
	}
	engine2, _ := newTestEngine(t, execEndless)
	result2, err := engine2.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{{ID: "loop", Tool: "loop", OnFail: "goto:loop"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Success {
		t.Fatal("endless goto loop should fail")
	}
	if endless > maxGotoJumps+1 {
		t.Fatalf("jump budget not enforced: %d executions", endless)
	}
}

func TestCampaignParallel(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		mu.Lock()
		calls[tool]++
		mu.Unlock()
		if tool == "bad" {
			return "failed", false, nil
		}
		return "ok", true, nil
	}

	engine, _ := newTestEngine(t, exec)
	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{Parallel: []EnhancedStep{
				{ID: "p1", Tool: "t1"},
				{ID: "p2", Tool: "t2"},
				{ID: "p3", Tool: "t3"},
			}},
			{Tool: "after"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("parallel campaign failed: %+v", result)
	}
	for _, name := range []string{"t1", "t2", "t3", "after"} {
		if calls[name] != 1 {
			t.Errorf("expected %s called once, got %d", name, calls[name])
		}
	}

	// Parallel failure without on_fail stops the campaign.
	engine2, _ := newTestEngine(t, exec)
	result2, err := engine2.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{Parallel: []EnhancedStep{
				{Tool: "good"},
				{Tool: "bad"},
			}},
			{Tool: "never"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Success || calls["never"] != 0 {
		t.Fatalf("parallel failure should stop campaign: %+v", result2)
	}

	// on_fail=continue tolerates parallel failures.
	engine3, _ := newTestEngine(t, exec)
	result3, err := engine3.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{Parallel: []EnhancedStep{
				{Tool: "good"},
				{Tool: "bad"},
			}, OnFail: "continue"},
			{Tool: "after"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result3.Success {
		t.Fatalf("on_fail=continue should tolerate parallel failure: %+v", result3)
	}
}

func TestCampaignResume(t *testing.T) {
	release := make(chan struct{})
	var resumed bool
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		if tool == "first" {
			return "first done", true, nil
		}
		if tool == "blocked" {
			select {
			case <-ctx.Done():
				return "", false, ctx.Err()
			case <-release:
				resumed = true
				return "unblocked", true, nil
			}
		}
		return "done", true, nil
	}

	engine, _ := newTestEngine(t, exec)
	runCtx, cancel := context.WithCancel(context.Background())
	go func() {
		_, _ = engine.RunEnhanced(runCtx, &EnhancedWorkflowRequest{
			ID: "resume-test",
			Steps: []EnhancedStep{
				{ID: "first", Tool: "first"},
				{ID: "blocked", Tool: "blocked"},
				{ID: "last", Tool: "last"},
			},
		})
	}()

	// Wait until the campaign is running the blocked step, then cancel.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := engine.Status("resume-test")
		if err == nil && state.Status == "running" && state.NextIndex >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := engine.Status("resume-test")
		if err == nil && (state.Status == "paused" || state.Status == "cancelled") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	state, err := engine.Status("resume-test")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if state.Status != "paused" && state.Status != "cancelled" {
		t.Fatalf("expected paused/cancelled, got %s", state.Status)
	}

	close(release)
	result, err := engine.Resume(context.Background(), "resume-test")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !result.Success || !resumed {
		t.Fatalf("resumed campaign should complete: success=%v resumed=%v", result.Success, resumed)
	}
}

func TestCampaignCancel(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		close(started)
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		case <-release:
			return "done", true, nil
		}
	}
	engine, _ := newTestEngine(t, exec)

	go func() {
		_, _ = engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
			ID:    "cancel-test",
			Steps: []EnhancedStep{{ID: "hang", Tool: "hang"}},
		})
	}()

	<-started
	if err := engine.Cancel("cancel-test"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	state, err := engine.Status("cancel-test")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if state.Status != "cancelled" {
		t.Fatalf("expected cancelled state, got %s", state.Status)
	}
	close(release)

	// Cancelling something unknown errors.
	if err := engine.Cancel("does-not-exist"); err == nil {
		t.Fatal("expected error cancelling unknown workflow")
	}
}

func TestCampaignValidation(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return "ok", true, nil
	}
	engine, _ := newTestEngine(t, exec)
	ctx := context.Background()

	tooMany := make([]EnhancedStep, maxCampaignSteps+1)
	for i := range tooMany {
		tooMany[i] = EnhancedStep{Tool: "t"}
	}
	if _, err := engine.RunEnhanced(ctx, &EnhancedWorkflowRequest{Steps: tooMany}); err == nil {
		t.Error("expected step limit error")
	}

	bigParallel := make([]EnhancedStep, maxParallelGroup+1)
	for i := range bigParallel {
		bigParallel[i] = EnhancedStep{Tool: "t"}
	}
	if _, err := engine.RunEnhanced(ctx, &EnhancedWorkflowRequest{Steps: []EnhancedStep{{Parallel: bigParallel}}}); err == nil {
		t.Error("expected parallel group limit error")
	}

	if _, err := engine.RunEnhanced(ctx, &EnhancedWorkflowRequest{Steps: []EnhancedStep{
		{Parallel: []EnhancedStep{{Parallel: []EnhancedStep{{Tool: "t"}}}}},
	}}); err == nil {
		t.Error("expected nested parallel error")
	}

	if _, err := engine.RunEnhanced(ctx, &EnhancedWorkflowRequest{Steps: []EnhancedStep{
		{Tool: "t", OnFail: "explode"},
	}}); err == nil {
		t.Error("expected invalid on_fail error")
	}

	if _, err := engine.RunEnhanced(ctx, &EnhancedWorkflowRequest{Steps: []EnhancedStep{
		{Tool: "t", Condition: &Condition{Op: "definitely-not-an-op"}},
	}}); err == nil {
		t.Error("expected invalid condition op error")
	}

	if _, err := engine.RunEnhanced(ctx, &EnhancedWorkflowRequest{Steps: []EnhancedStep{
		{ID: "dup", Tool: "t"}, {ID: "dup", Tool: "t"},
	}}); err == nil {
		t.Error("expected duplicate id error")
	}

	if _, err := engine.RunEnhanced(ctx, &EnhancedWorkflowRequest{Steps: []EnhancedStep{
		{Tool: "t", Parallel: []EnhancedStep{{Tool: "t"}}},
	}}); err == nil {
		t.Error("expected tool+parallel conflict error")
	}

	// Path traversal via workflow id is rejected.
	if _, err := engine.RunEnhanced(ctx, &EnhancedWorkflowRequest{ID: "../../etc/passwd", Steps: []EnhancedStep{{Tool: "t"}}}); err == nil {
		t.Error("expected invalid workflow id error")
	}
	if _, err := engine.Status("../escape"); err == nil {
		t.Error("expected invalid workflow id error on status")
	}
	if _, err := engine.Resume(ctx, "a/b"); err == nil {
		t.Error("expected invalid workflow id error on resume")
	}
}

func TestCampaignTemplates(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		if string(params) == `{"domain":"example.com"}` {
			return "found subdomains", true, nil
		}
		return fmt.Sprintf("params: %s", params), true, nil
	}
	engine, _ := newTestEngine(t, exec)

	// Save a template via the JSON handler (validates steps).
	tmpl := `{"name":"mini-recon","description":"test playbook","vars":[{"name":"domain","required":true}],"steps":[{"id":"enum","tool":"subfinder_enum","params":{"domain":"{{domain}}"}},{"id":"probe","tool":"httpx_probe","params":{"target":"${enum.text}"}}]}`
	if _, err := engine.SaveTemplateFromJSON(json.RawMessage(tmpl)); err != nil {
		t.Fatalf("save template: %v", err)
	}

	// Path traversal in template names is rejected.
	if _, err := engine.SaveTemplateFromJSON(json.RawMessage(`{"name":"../evil","steps":[{"tool":"t"}]}`)); err == nil {
		t.Fatal("expected template name validation error")
	}

	// List and get.
	listData, err := engine.TemplatesFromJSON(nil)
	if err != nil {
		t.Fatalf("list templates: %v", err)
	}
	if !strings.Contains(string(listData), "mini-recon") {
		t.Fatalf("template missing from list: %s", listData)
	}
	getData, err := engine.GetTemplateFromJSON(json.RawMessage(`{"name":"mini-recon"}`))
	if err != nil {
		t.Fatalf("get template: %v", err)
	}
	if !strings.Contains(string(getData), "subfinder_enum") {
		t.Fatalf("template content wrong: %s", getData)
	}

	// Run from template.
	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Template: "mini-recon",
		Vars:     map[string]string{"domain": "example.com"},
	})
	if err != nil {
		t.Fatalf("run template: %v", err)
	}
	if !result.Success {
		t.Fatalf("template run failed: %+v", result)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(result.Steps))
	}

	// Missing required var errors.
	if _, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{Template: "mini-recon"}); err == nil {
		t.Fatal("expected missing-variable error")
	}
}

func TestCampaignJSONHandlers(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return "ok", true, nil
	}
	engine, _ := newTestEngine(t, exec)

	runData, err := engine.RunFromJSON(context.Background(), json.RawMessage(
		`{"id":"handler-test","steps":[{"id":"one","tool":"t1"}]}`))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var runResult WorkflowResult
	if err := json.Unmarshal(runData, &runResult); err != nil {
		t.Fatalf("unmarshal run result: %v", err)
	}
	if runResult.WorkflowID != "handler-test" || !runResult.Success {
		t.Fatalf("unexpected run result: %s", runData)
	}

	statusData, err := engine.StatusFromJSON(json.RawMessage(`{"workflow_id":"handler-test"}`))
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(string(statusData), `"completed"`) {
		t.Fatalf("unexpected status: %s", statusData)
	}

	listData, err := engine.ListFromJSON(nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(string(listData), "handler-test") {
		t.Fatalf("campaign missing from list: %s", listData)
	}

	if _, err := engine.RunFromJSON(context.Background(), json.RawMessage(`{"steps":[{"tool":"t","bogus_field":1}]}`)); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
	if _, err := engine.CancelFromJSON(json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected missing workflow_id error")
	}
}

func TestCampaignSkippedStepsAvailableViaID(t *testing.T) {
	var captured json.RawMessage
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		if tool == "final" {
			captured = params
		}
		return `{"v":1}`, true, nil
	}
	engine, _ := newTestEngine(t, exec)
	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{ID: "maybe", Tool: "t", Condition: &Condition{Step: "0", Op: "failure"}},
			{ID: "final", Tool: "final", Params: json.RawMessage(`{"x":"${maybe.text}"}`)},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("campaign failed: %+v", result)
	}
	if !result.Steps[0].Skipped {
		t.Fatalf("expected first step to be skipped: %+v", result.Steps[0])
	}
	if !strings.Contains(string(captured), "skipped: condition not met") {
		t.Fatalf("skipped step text should be referenceable, got params %s", captured)
	}
}

func TestCampaignOutputBudget(t *testing.T) {
	big := strings.Repeat("x", 1024*1024)
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return big, true, nil
	}
	engine, _ := newTestEngine(t, exec)
	steps := make([]EnhancedStep, 20)
	for i := range steps {
		steps[i] = EnhancedStep{Tool: "t"}
	}
	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{Steps: steps})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected output budget failure")
	}
	if result.Status != "failed" {
		t.Fatalf("expected failed status, got %s", result.Status)
	}
}

func TestMain(m *testing.M) {
	// StateManager writes into temp dirs; keep umask predictable.
	os.Exit(m.Run())
}

// TestPlaybookTemplatesValidate loads the playbooks shipped in the repository
// and runs them through the same validation as campaign/template/save.
func TestPlaybookTemplatesValidate(t *testing.T) {
	playbookDir := filepath.Join("..", "..", "playbooks")
	entries, err := os.ReadDir(playbookDir)
	if err != nil {
		t.Fatalf("read playbooks dir: %v", err)
	}
	found := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		found++
		data, err := os.ReadFile(filepath.Join(playbookDir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		var tmpl Template
		if err := json.Unmarshal(data, &tmpl); err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		if tmpl.Name == "" || len(tmpl.Steps) == 0 {
			t.Fatalf("%s: template needs a name and steps", entry.Name())
		}
		if err := validateSteps(tmpl.Steps); err != nil {
			t.Fatalf("%s: invalid steps: %v", entry.Name(), err)
		}
		// Template variables must all be declared in vars.
		declared := make(map[string]bool, len(tmpl.Vars))
		for _, v := range tmpl.Vars {
			declared[v.Name] = true
		}
		body := string(data)
		for name := range declared {
			if !strings.Contains(body, "{{"+name+"}}") {
				t.Fatalf("%s: declared var %q never used", entry.Name(), name)
			}
		}
	}
	if found == 0 {
		t.Fatal("no playbooks found")
	}
}
