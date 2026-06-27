package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Definition is the JSON schema for a plugin tool definition.
type Definition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Binary      string          `json:"binary"`
	ArgsTemplate []string       `json:"args_template"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// PluginTool implements mcp.Tool from a JSON definition.
type PluginTool struct {
	def  Definition
	exec executor.Executor
}

func (t *PluginTool) Name() string        { return t.def.Name }
func (t *PluginTool) Description() string  { return t.def.Description }
func (t *PluginTool) InputSchema() json.RawMessage { return t.def.InputSchema }

func (t *PluginTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input map[string]any
	if err := json.Unmarshal(params, &input); err != nil {
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: "Error: invalid input: " + err.Error()}},
			IsError: true,
		}, nil
	}

	args := make([]string, 0, len(t.def.ArgsTemplate))
	for _, tmplStr := range t.def.ArgsTemplate {
		rendered, err := renderTemplate(tmplStr, input)
		if err != nil {
			return &mcp.ToolResult{
				Content: []mcp.ContentBlock{{Type: "text", Text: "Error: template rendering failed: " + err.Error()}},
				IsError: true,
			}, nil
		}
		if rendered != "" {
			args = append(args, rendered)
		}
	}

	result, err := t.exec.Run(ctx, t.def.Binary, args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return &mcp.ToolResult{
			Content: []mcp.ContentBlock{{Type: "text", Text: fmt.Sprintf("Error: %s\n%s", err.Error(), stderr)}},
			IsError: true,
		}, nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s\n\n", t.def.Name)
	output := strings.TrimSpace(string(result.Stdout))
	if output == "" {
		sb.WriteString("Command completed with no output.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}
	if len(result.Stderr) > 0 {
		sb.WriteString("\n**Stderr**:\n```\n")
		sb.WriteString(strings.TrimSpace(string(result.Stderr)))
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// LoadPlugins reads all .json files from the plugins directory and returns tools.
func LoadPlugins(dir string, exec executor.Executor) []mcp.Tool {
	if dir == "" {
		dir = "./plugins"
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		log.Printf("plugin: failed to read dir %s: %v", dir, err)
		return nil
	}

	var tools []mcp.Tool
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("plugin: failed to read %s: %v", path, err)
			continue
		}

		var def Definition
		if err := json.Unmarshal(data, &def); err != nil {
			log.Printf("plugin: invalid JSON in %s: %v", path, err)
			continue
		}

		if def.Name == "" || def.Binary == "" {
			log.Printf("plugin: skipping %s (missing name or binary)", path)
			continue
		}

		tools = append(tools, &PluginTool{def: def, exec: exec})
	}

	return tools
}

func renderTemplate(tmplStr string, data map[string]any) (string, error) {
	if !strings.Contains(tmplStr, "{{") {
		return tmplStr, nil
	}

	tmpl, err := template.New("arg").Option("missingkey=zero").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
