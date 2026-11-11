package reporting

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yasindce1998/redhands/pkg/evidence"
	"github.com/yasindce1998/redhands/pkg/executor"
)

func TestEvidenceListCombinesFiltersAndRejectsInvalidInput(t *testing.T) {
	s, err := evidence.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"tool-one", "host-one"}, {"tool-one", "host-two"}, {"tool-two", "host-one"}} {
		if _, err := s.SaveOutput(pair[0], pair[1], "evidence"); err != nil {
			t.Fatal(err)
		}
	}
	tool := NewEvidenceListTool(s)
	result, err := tool.Execute(context.Background(), json.RawMessage(`{"tool":"tool-one","host":"host-one"}`))
	if err != nil || result.IsError {
		t.Fatalf("list failed: %+v %v", result, err)
	}
	var items []*evidence.Item
	if err := json.Unmarshal([]byte(result.Content[0].Text), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Host != "host-one" || items[0].Tool != "tool-one" {
		t.Fatalf("filters not intersected: %+v", items)
	}
	result, err = tool.Execute(context.Background(), json.RawMessage(`{"host":123}`))
	if err != nil || !result.IsError {
		t.Fatal("invalid evidence filter accepted")
	}
}

func TestScreenshotValidationAndExecutorAllowlist(t *testing.T) {
	s, err := evidence.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exec := executor.New(executor.Config{Timeout: 1, MaxOutputBytes: 1024, AllowedBinaries: map[string]string{}})
	tool := NewEvidenceScreenshotTool(s, exec)
	for _, params := range []string{`{"url":"file:///etc/passwd"}`, `{"url":123}`, `{"url":"https://example.test"}`} {
		result, err := tool.Execute(context.Background(), json.RawMessage(params))
		if err != nil || !result.IsError {
			t.Fatalf("unsafe/disabled screenshot accepted: %+v %v", result, err)
		}
	}
	if len(s.List()) != 0 {
		t.Fatal("failed screenshot indexed")
	}
}
