package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/pkg/version"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	InformationURI  string              `json:"informationUri"`
	Rules           []sarifRule         `json:"rules,omitempty"`
	SemanticVersion string              `json:"semanticVersion"`
	Properties      sarifToolProperties `json:"properties,omitempty"`
}

type sarifToolProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifMessage     `json:"message"`
	Locations  []sarifLocation  `json:"locations,omitempty"`
	Properties sarifResultProps `json:"properties,omitempty"`
}

type sarifResultProps struct {
	Host      string   `json:"host,omitempty"`
	Tool      string   `json:"tool,omitempty"`
	MITRE     []string `json:"mitre,omitempty"`
	RiskScore float64  `json:"riskScore,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLoc     `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLoc struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func severityToLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "none"
	}
}

func GenerateSARIF(findings []*targetdb.Finding, toolVersion string) ([]byte, error) {
	if toolVersion == "" {
		toolVersion = version.Version
	}

	ruleMap := make(map[string]bool)
	var rules []sarifRule
	results := make([]sarifResult, 0, len(findings))

	for _, f := range findings {
		ruleID := fmt.Sprintf("RH-%s", f.ID)

		if !ruleMap[ruleID] {
			ruleMap[ruleID] = true
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription:  sarifMessage{Text: f.Description},
				Properties:       sarifRuleProperties{Tags: f.MITRE},
			})
		}

		result := sarifResult{
			RuleID:  ruleID,
			Level:   severityToLevel(f.Severity),
			Message: sarifMessage{Text: f.Description},
			Properties: sarifResultProps{
				Host:      f.Host,
				Tool:      f.Tool,
				MITRE:     f.MITRE,
				RiskScore: f.RiskScore,
				Timestamp: f.Timestamp.Format(time.RFC3339),
			},
		}

		if f.Host != "" {
			result.Locations = []sarifLocation{{
				LogicalLocations: []sarifLogicalLoc{{
					Name: f.Host,
					Kind: "host",
				}},
			}}
		}

		results = append(results, result)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:            "RedHands",
					Version:         toolVersion,
					SemanticVersion: toolVersion,
					InformationURI:  "https://github.com/yasindce1998/redhands",
					Rules:           rules,
				},
			},
			Results: results,
		}},
	}

	return json.MarshalIndent(log, "", "  ")
}
