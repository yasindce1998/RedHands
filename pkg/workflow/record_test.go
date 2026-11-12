package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// fakeRecorder captures RecordStep calls.
type fakeRecorder struct {
	calls []fakeRecorderCall
	fail  bool
}

type fakeRecorderCall struct {
	workflowID string
	stepID     string
	tool       string
	rule       RecordRule
	items      []any
	mitre      []string
}

func (f *fakeRecorder) RecordStep(workflowID, stepID, tool string, rule RecordRule, items []any, stepMITRE []string) error {
	if f.fail {
		return fmt.Errorf("recorder unavailable")
	}
	f.calls = append(f.calls, fakeRecorderCall{workflowID, stepID, tool, rule, items, stepMITRE})
	return nil
}

func TestCampaignRecordRules(t *testing.T) {
	recorder := &fakeRecorder{}
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		switch tool {
		case "scan":
			return "```json\n{\"hosts\":[{\"ip\":\"10.0.0.1\",\"hostname\":\"web\"},{\"ip\":\"10.0.0.2\"}]}\n```", true, nil
		case "bruteforce":
			return `{"creds":[{"user":"admin","pass":"secret"}]}`, true, nil
		case "plain":
			return "not json at all", true, nil
		}
		return "ok", true, nil
	}
	engine, _ := newTestEngine(t, exec)
	engine.SetRecorder(recorder)

	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID: "record-test",
		Steps: []EnhancedStep{
			{ID: "scan", Tool: "scan", Record: []RecordRule{
				{Type: "host", Path: "hosts", Fields: map[string]string{"ip": "ip", "hostname": "hostname"}},
			}},
			{ID: "creds", Tool: "bruteforce", Record: []RecordRule{
				{Type: "credential", Path: "creds", Fields: map[string]string{"username": "user", "secret": "pass"}},
			}},
			{ID: "plain", Tool: "plain", Record: []RecordRule{
				{Type: "host", Path: "hosts", Fields: map[string]string{"ip": "ip"}},
			}},
			{ID: "missing", Tool: "scan", Record: []RecordRule{
				{Type: "host", Path: "nope", Fields: map[string]string{"ip": "ip"}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("campaign failed: %+v", result)
	}
	if len(recorder.calls) != 2 {
		t.Fatalf("expected 2 recorded rules, got %d", len(recorder.calls))
	}
	if recorder.calls[0].workflowID != "record-test" || recorder.calls[0].stepID != "scan" {
		t.Errorf("first call context wrong: %+v", recorder.calls[0])
	}
	if len(recorder.calls[0].items) != 2 {
		t.Errorf("expected 2 host items, got %d", len(recorder.calls[0].items))
	}
	if len(recorder.calls[1].items) != 1 {
		t.Errorf("expected 1 credential item, got %d", len(recorder.calls[1].items))
	}
	if result.Steps[0].Recorded != 2 {
		t.Errorf("step 0 should report 2 recorded items, got %d", result.Steps[0].Recorded)
	}
	// Unstructured output and missing paths record nothing and keep going.
	if result.Steps[2].Recorded != 0 || !contains(result.Steps[2].Text, "not structured JSON") {
		t.Errorf("unstructured recording should warn: %+v", result.Steps[2])
	}
	if result.Steps[3].Recorded != 0 || !contains(result.Steps[3].Text, "not found") {
		t.Errorf("missing path should warn: %+v", result.Steps[3])
	}
}

func TestCampaignRecorderFailureIsNotFatal(t *testing.T) {
	recorder := &fakeRecorder{fail: true}
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return `{"hosts":[{"ip":"10.0.0.1"}]}`, true, nil
	}
	engine, _ := newTestEngine(t, exec)
	engine.SetRecorder(recorder)

	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{ID: "scan", Tool: "scan", Record: []RecordRule{
				{Type: "host", Path: "hosts", Fields: map[string]string{"ip": "ip"}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("recorder failure must not fail the campaign: %+v", result)
	}
	if !contains(result.Steps[0].Text, "recording warning") {
		t.Errorf("expected recording warning in step text: %+v", result.Steps[0])
	}
}

func TestCampaignMITRETagging(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return "ok", true, nil
	}
	engine, _ := newTestEngine(t, exec)

	result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{
			{ID: "a", Tool: "t", MITRE: []string{"T1613", "t1552.007"}},
			{ID: "b", Tool: "t", MITRE: []string{"T1613"}},
			{ID: "skipped", Tool: "t", MITRE: []string{"T9999"}, Condition: &Condition{Step: "$prev", Op: "failure"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Deduplicated, normalized, skipped steps excluded.
	if len(result.MITRE) != 2 || result.MITRE[0] != "T1613" || result.MITRE[1] != "T1552.007" {
		t.Fatalf("unexpected MITRE aggregation: %v", result.MITRE)
	}

	// Invalid IDs are rejected up front.
	engine2, _ := newTestEngine(t, exec)
	if _, err := engine2.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		Steps: []EnhancedStep{{Tool: "t", MITRE: []string{"not-a-technique"}}},
	}); err == nil {
		t.Fatal("expected invalid MITRE ID error")
	}
}

func TestCampaignRecordRuleValidation(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return "ok", true, nil
	}
	engine, _ := newTestEngine(t, exec)
	for _, rule := range []RecordRule{
		{Type: "wallet", Path: "x", Fields: map[string]string{"a": "b"}},
		{Type: "host", Fields: map[string]string{"a": "b"}},
		{Type: "host", Path: "x"},
	} {
		if _, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
			Steps: []EnhancedStep{{Tool: "t", Record: []RecordRule{rule}}},
		}); err == nil {
			t.Errorf("expected validation error for %+v", rule)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
