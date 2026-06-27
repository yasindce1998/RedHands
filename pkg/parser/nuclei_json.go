package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
)

// NucleiJSONParser parses nuclei JSONL output (one JSON object per line).
type NucleiJSONParser struct{}

func (p *NucleiJSONParser) Name() string { return "nuclei_json" }

func (p *NucleiJSONParser) Parse(data []byte) (json.RawMessage, error) {
	var findings []nucleiFinding

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw nucleiRawFinding
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}

		findings = append(findings, nucleiFinding{
			TemplateID: raw.TemplateID,
			Name:       raw.Info.Name,
			Severity:   raw.Info.Severity,
			Host:       raw.Host,
			MatchedAt:  raw.MatchedAt,
			Type:       raw.Type,
			IP:         raw.IP,
			URL:        raw.URL,
			Matched:    raw.Matched,
			ExtractedResults: raw.ExtractedResults,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("nuclei json parse: %w", err)
	}

	result := nucleiResult{
		TotalFindings: len(findings),
		Findings:      findings,
	}

	return json.Marshal(result)
}

type nucleiRawFinding struct {
	TemplateID       string   `json:"template-id"`
	Info             nucleiInfo `json:"info"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	Type             string   `json:"type"`
	IP               string   `json:"ip"`
	URL              string   `json:"url"`
	Matched          string   `json:"matched"`
	ExtractedResults []string `json:"extracted-results"`
}

type nucleiInfo struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

type nucleiResult struct {
	TotalFindings int              `json:"total_findings"`
	Findings      []nucleiFinding  `json:"findings"`
}

type nucleiFinding struct {
	TemplateID       string   `json:"template_id"`
	Name             string   `json:"name"`
	Severity         string   `json:"severity"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched_at,omitempty"`
	Type             string   `json:"type,omitempty"`
	IP               string   `json:"ip,omitempty"`
	URL              string   `json:"url,omitempty"`
	Matched          string   `json:"matched,omitempty"`
	ExtractedResults []string `json:"extracted_results,omitempty"`
}
