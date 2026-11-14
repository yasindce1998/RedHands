package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// GenerateInput is the parameter set for sbom_generate.
type GenerateInput struct {
	Source           string `json:"source"`
	Format           string `json:"format,omitempty"`
	OutputFile       string `json:"output_file,omitempty"`
	SelectCatalogers string `json:"select_catalogers,omitempty"`
}

// GenerateTool wraps `syft <source>` to produce a Software Bill of Materials.
type GenerateTool struct {
	exec executor.Executor
}

// NewSbomGenerate returns a syft-backed SBOM generation tool.
func NewSbomGenerate(exec executor.Executor) *GenerateTool {
	return &GenerateTool{exec: exec}
}

func (t *GenerateTool) Name() string { return "sbom_generate" }

func (t *GenerateTool) Description() string {
	return "Generate a Software Bill of Materials (SBOM) from a container image or filesystem with Anchore syft. " +
		"The source can be an image reference (alpine:latest, registry:..., docker:... — these pull from registries or a container daemon and need network access) " +
		"or a local path form (dir:/path, file:/path, docker-archive:./image.tar, oci-dir:...) which is fully offline. " +
		"Output formats: syft-json (default, feeds vuln_scan_sbom), cyclonedx-json, spdx-json. " +
		"Returns an artifact/package summary plus the full SBOM JSON in a ```json fence for campaign record rules; " +
		"an additional copy can be written to output_file (syft -o <format>=<path>)."
}

func (t *GenerateTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"source": {
				"type": "string",
				"description": "Syft source: image reference (alpine:latest, registry:host/img:tag, docker:img) or path form (dir:/path, file:/path, docker-archive:./img.tar, oci-dir:/path). Image references pull from registries = network"
			},
			"format": {
				"type": "string",
				"enum": ["syft-json", "cyclonedx-json", "spdx-json"],
				"description": "SBOM output format (default syft-json)"
			},
			"output_file": {
				"type": "string",
				"description": "Optional path to also write the SBOM file to (passed as -o <format>=<path>; stdout JSON is still captured and returned)"
			},
			"select_catalogers": {
				"type": "string",
				"description": "Optional --select-catalogers expression to add/remove/filter package catalogers (e.g. +python,-rpm or a comma-separated list)"
			}
		},
		"required": ["source"]
	}`)
}

func (t *GenerateTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input GenerateInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSource(input.Source, "source"); err != nil {
		return errorResult(err.Error()), nil
	}
	format := "syft-json"
	if input.Format != "" {
		if _, ok := sbomFormats[input.Format]; !ok {
			return errorResult("format must be one of: syft-json, cyclonedx-json, spdx-json"), nil
		}
		format = input.Format
	}
	if err := validatePath(input.OutputFile, "output_file"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateCatalogers(input.SelectCatalogers); err != nil {
		return errorResult(err.Error()), nil
	}

	// syft -o <format> emits the SBOM on stdout (captured here and fenced
	// below); an additional -o <format>=<path> writes a file copy. syft
	// supports multiple -o flags, so both outputs coexist (verified against
	// syft v1.57.1 cmd/syft/internal/options/output.go: AllowMultipleOutputs).
	args := []string{input.Source, "-o", format}
	if input.OutputFile != "" {
		args = append(args, "-o", format+"="+input.OutputFile)
	}
	if input.SelectCatalogers != "" {
		args = append(args, "--select-catalogers", input.SelectCatalogers)
	}

	result, err := t.exec.Run(ctx, "syft", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("syft failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## SBOM Generation (syft)\n\n")
	fmt.Fprintf(&sb, "- **Source:** %s\n", input.Source)
	fmt.Fprintf(&sb, "- **Format:** %s\n", format)
	if input.OutputFile != "" {
		fmt.Fprintf(&sb, "- **File:** %s\n", input.OutputFile)
	}
	if input.SelectCatalogers != "" {
		fmt.Fprintf(&sb, "- **Catalogers:** %s\n", input.SelectCatalogers)
	}
	sb.WriteString("\n")

	if summary, ok := summarizeSBOM(output); ok {
		sb.WriteString(summary)
		sb.WriteString("\n")
	} else if output == "" && input.OutputFile != "" {
		sb.WriteString("SBOM written to the output file (no stdout to summarize).\n\n")
	}

	switch {
	case output != "" && json.Valid([]byte(output)):
		sb.WriteString("```json\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	case output != "":
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	default:
		sb.WriteString("No SBOM output captured on stdout.\n")
	}

	return textResult(sb.String()), nil
}

// sbomDocument mirrors the subset of the syft-json shape the summary reads:
// artifacts (packages), source, distro, descriptor. For cyclonedx/spdx
// formats the parse simply fails and the raw JSON is passed through.
type sbomDocument struct {
	Artifacts []sbomArtifact `json:"artifacts"`
	Source    struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"source"`
	Distro struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"distro"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
}

type sbomArtifact struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Language string `json:"language"`
	Purl     string `json:"purl"`
}

// summarizeSBOM renders an artifact/package summary from syft-json stdout.
// It returns ok=false when the output is not recognizable syft-json (e.g. a
// cyclonedx/spdx document), in which case the caller passes the raw output
// through unchanged.
func summarizeSBOM(output string) (string, bool) {
	if output == "" || !json.Valid([]byte(output)) {
		return "", false
	}
	var doc sbomDocument
	if err := json.Unmarshal([]byte(output), &doc); err != nil || len(doc.Artifacts) == 0 {
		return "", false
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "- **Packages:** %d\n", len(doc.Artifacts))
	if doc.Source.Type != "" || doc.Source.Name != "" {
		fmt.Fprintf(&sb, "- **Source:** %s (%s)\n", doc.Source.Name, doc.Source.Type)
	}
	if doc.Distro.Name != "" {
		fmt.Fprintf(&sb, "- **Distro:** %s %s\n", doc.Distro.Name, doc.Distro.Version)
	}
	if doc.Descriptor.Version != "" {
		fmt.Fprintf(&sb, "- **Syft version:** %s\n", doc.Descriptor.Version)
	}

	// Package-type breakdown, most common first.
	typeCounts := make(map[string]int)
	for _, a := range doc.Artifacts {
		key := a.Type
		if key == "" {
			key = "unknown"
		}
		typeCounts[key]++
	}
	types := make([]string, 0, len(typeCounts))
	for ty := range typeCounts {
		types = append(types, ty)
	}
	sort.Slice(types, func(i, j int) bool {
		if typeCounts[types[i]] != typeCounts[types[j]] {
			return typeCounts[types[i]] > typeCounts[types[j]]
		}
		return types[i] < types[j]
	})
	if len(types) > 5 {
		types = types[:5]
	}
	sb.WriteString("- **Package types:** ")
	for i, ty := range types {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "%s (%d)", ty, typeCounts[ty])
	}
	sb.WriteString("\n")

	// First few packages as a preview.
	preview := doc.Artifacts
	if len(preview) > 5 {
		preview = preview[:5]
	}
	sb.WriteString("- **Sample packages:**\n")
	for _, a := range preview {
		purl := a.Purl
		if purl == "" {
			purl = a.Name + "@" + a.Version
		}
		fmt.Fprintf(&sb, "  - %s\n", purl)
	}
	return sb.String(), true
}
