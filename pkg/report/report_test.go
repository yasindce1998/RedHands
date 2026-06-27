package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarkdownOutputStructure(t *testing.T) {
	gen := NewGenerator()
	req := &Request{
		Title: "Pentest Report",
		Sections: []Section{
			{Title: "Port Scan", Tool: "nmap", Content: "Found ports 80, 443 open"},
			{Title: "Vulnerabilities", Tool: "nuclei", Content: "CVE-2024-1234 found"},
		},
		Format: "markdown",
	}

	output, err := gen.Generate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check title
	if !strings.Contains(output, "# Pentest Report") {
		t.Error("markdown output missing title")
	}

	// Check table of contents
	if !strings.Contains(output, "## Table of Contents") {
		t.Error("markdown output missing TOC")
	}
	if !strings.Contains(output, "Port Scan") {
		t.Error("TOC missing 'Port Scan' entry")
	}
	if !strings.Contains(output, "Vulnerabilities") {
		t.Error("TOC missing 'Vulnerabilities' entry")
	}

	// Check sections
	if !strings.Contains(output, "## 1. Port Scan") {
		t.Error("markdown output missing section 1")
	}
	if !strings.Contains(output, "## 2. Vulnerabilities") {
		t.Error("markdown output missing section 2")
	}

	// Check tool references
	if !strings.Contains(output, "*Tool: nmap*") {
		t.Error("markdown output missing tool reference for nmap")
	}
	if !strings.Contains(output, "*Tool: nuclei*") {
		t.Error("markdown output missing tool reference for nuclei")
	}

	// Check content
	if !strings.Contains(output, "Found ports 80, 443 open") {
		t.Error("markdown output missing section content")
	}

	// Check footer
	if !strings.Contains(output, "RedHands MCP Server") {
		t.Error("markdown output missing footer")
	}
}

func TestHTMLOutputStructure(t *testing.T) {
	gen := NewGenerator()
	req := &Request{
		Title: "Security Assessment",
		Sections: []Section{
			{Title: "Network Scan", Tool: "masscan", Content: "Host 192.168.1.1 has open ports"},
		},
		Format: "html",
	}

	output, err := gen.Generate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check HTML doctype
	if !strings.HasPrefix(output, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}

	// Check title element
	if !strings.Contains(output, "<title>Security Assessment</title>") {
		t.Error("HTML output missing <title> tag")
	}

	// Check heading
	if !strings.Contains(output, "<h1>Security Assessment</h1>") {
		t.Error("HTML output missing h1 heading")
	}

	// Check TOC
	if !strings.Contains(output, "Table of Contents") {
		t.Error("HTML output missing Table of Contents")
	}
	if !strings.Contains(output, "Network Scan") {
		t.Error("HTML output missing section link in TOC")
	}

	// Check section heading
	if !strings.Contains(output, `<h2 id="section-1">1. Network Scan</h2>`) {
		t.Error("HTML output missing section heading with id")
	}

	// Check tool tag
	if !strings.Contains(output, "masscan") {
		t.Error("HTML output missing tool reference")
	}

	// Check content
	if !strings.Contains(output, "Host 192.168.1.1 has open ports") {
		t.Error("HTML output missing section content")
	}

	// Check footer
	if !strings.Contains(output, "RedHands MCP Server") {
		t.Error("HTML output missing footer")
	}

	// Check closing tags
	if !strings.Contains(output, "</body>") {
		t.Error("HTML output missing closing body tag")
	}
	if !strings.Contains(output, "</html>") {
		t.Error("HTML output missing closing html tag")
	}
}

func TestGenerateFromJSONValid(t *testing.T) {
	gen := NewGenerator()

	input := json.RawMessage(`{
		"title": "JSON Report",
		"format": "markdown",
		"sections": [
			{"title": "Findings", "tool": "scanner", "content": "All clear"}
		]
	}`)

	output, err := gen.GenerateFromJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "# JSON Report") {
		t.Error("GenerateFromJSON did not produce expected title")
	}
	if !strings.Contains(output, "All clear") {
		t.Error("GenerateFromJSON did not include section content")
	}
}

func TestGenerateFromJSONInvalid(t *testing.T) {
	gen := NewGenerator()

	_, err := gen.GenerateFromJSON(json.RawMessage(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON input")
	}
}

func TestEmptyTitleGetsDefault(t *testing.T) {
	gen := NewGenerator()
	req := &Request{
		Title:    "",
		Sections: []Section{{Title: "Test", Content: "data"}},
		Format:   "markdown",
	}

	output, err := gen.Generate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "# Security Assessment Report") {
		t.Error("empty title should default to 'Security Assessment Report'")
	}
}

func TestUnsupportedFormatReturnsError(t *testing.T) {
	gen := NewGenerator()
	req := &Request{
		Title:    "Test",
		Sections: []Section{{Title: "S1", Content: "c"}},
		Format:   "pdf",
	}

	_, err := gen.Generate(req)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error message should mention unsupported format, got: %v", err)
	}
	if !strings.Contains(err.Error(), "pdf") {
		t.Errorf("error message should mention the format name, got: %v", err)
	}
}

func TestDefaultFormatIsMarkdown(t *testing.T) {
	gen := NewGenerator()
	req := &Request{
		Title:    "No Format",
		Sections: []Section{{Title: "S", Content: "c"}},
		Format:   "", // empty format
	}

	output, err := gen.Generate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Markdown format starts with "# "
	if !strings.HasPrefix(output, "# No Format") {
		t.Error("empty format should default to markdown")
	}
}

func TestHTMLEscaping(t *testing.T) {
	gen := NewGenerator()
	req := &Request{
		Title:    "<script>alert('xss')</script>",
		Sections: []Section{{Title: "A & B", Content: "x < y && y > z"}},
		Format:   "html",
	}

	output, err := gen.Generate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(output, "<script>") {
		t.Error("HTML output should escape script tags")
	}
	if !strings.Contains(output, "&lt;script&gt;") {
		t.Error("HTML output should contain escaped script tag")
	}
	if !strings.Contains(output, "A &amp; B") {
		t.Error("HTML output should escape ampersands in section titles")
	}
}
