package reporting

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/pkg/version"
)

func TestSARIFFiltersAndVersion(t *testing.T) {
	db := targetdb.NewStore("", false)
	for _, finding := range []*targetdb.Finding{{Host: "192.0.2.1", Severity: "critical", Title: "A"}, {Host: "192.0.2.1", Severity: "high", Title: "B"}, {Host: "192.0.2.1", Severity: "low", Title: "C"}, {Host: "192.0.2.2", Severity: "critical", Title: "D"}} {
		if err := db.AddFinding(finding); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewSARIFTool(db).Execute(context.Background(), json.RawMessage(`{"host_filter":"192.0.2.1","severity_filter":"high"}`))
	if err != nil || r.IsError {
		t.Fatalf("report failed: %+v %v", r, err)
	}
	var document struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(r.Content[0].Text), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Runs[0].Results) != 2 {
		t.Fatalf("wrong filtered findings: %s", r.Content[0].Text)
	}
	if document.Runs[0].Tool.Driver.Version != version.Version {
		t.Fatal("inconsistent report version")
	}
	empty, err := NewSARIFTool(targetdb.NewStore("", false)).Execute(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(empty.Content[0].Text), &raw); err != nil {
		t.Fatal(err)
	}
}

func TestReportsRejectInvalidParameters(t *testing.T) {
	db := targetdb.NewStore("", false)
	for _, tool := range []mcp.Tool{NewSARIFTool(db), NewExecutiveSummaryTool(db), NewComplianceTool(db)} {
		r, err := tool.Execute(context.Background(), json.RawMessage(`{"format":123,"framework":123,"host_filter":123}`))
		if err != nil || !r.IsError {
			t.Errorf("%s silently ignored malformed parameters", tool.Name())
		}
	}
	r, _ := NewExecutiveSummaryTool(db).Execute(context.Background(), json.RawMessage(`{"format":"typo"}`))
	if !r.IsError {
		t.Fatal("invalid format ignored")
	}
}
