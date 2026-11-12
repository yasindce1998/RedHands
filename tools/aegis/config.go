package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/redhands/pkg/mcp"
)

const (
	// maxConfigFileSize caps runtime config files accepted by the read tool.
	maxConfigFileSize = 1 << 20 // 1 MiB
	// config file permission enforced by the write tool.
	configFilePerm = 0600
)

const (
	defaultConfigThreshold  = 2  // matches defense::RuntimeConfig serde default
	defaultConfigWindowSecs = 30 // matches defense::RuntimeConfig serde default
	maxConfigWindowSecs     = 86400
)

// runtimeConfig mirrors defense::RuntimeConfig (defense/src/lib.rs), which
// the defense daemon hot-reloads every 5s when started with --config <path>.
type runtimeConfig struct {
	Threshold  int `json:"threshold"`
	WindowSecs int `json:"window_secs"`
}

// DefenseConfigReadTool reads and validates a defense runtime config file.
type DefenseConfigReadTool struct{}

// NewDefenseConfigRead constructs the aegis_defense_config_read tool.
func NewDefenseConfigRead() *DefenseConfigReadTool { return &DefenseConfigReadTool{} }

func (t *DefenseConfigReadTool) Name() string { return "aegis_defense_config_read" }

func (t *DefenseConfigReadTool) Description() string {
	return "Read and validate an Aegis-Shadow defense runtime config file (the JSON file passed as `defense --config <path>`, hot-reloaded every 5s). Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Read-only file analysis; never executes any binary. Reports the alert threshold (1-4) and correlation window, applying the engine's defaults (threshold 2, window 30s) for missing fields."
}

func (t *DefenseConfigReadTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"path": {
				"type": "string",
				"description": "Path to the defense runtime config JSON file"
			}
		},
		"required": ["path"]
	}`)
}

func (t *DefenseConfigReadTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateExistingFile(input.Path, "path", maxConfigFileSize); err != nil {
		return errorResult(err.Error()), nil
	}

	data, err := os.ReadFile(input.Path)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot read config file: %v", err)), nil
	}
	cfg, err := parseRuntimeConfig(data)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow Defense Runtime Config\n\n")
	fmt.Fprintf(&sb, "- **Path:** `%s`\n", input.Path)
	fmt.Fprintf(&sb, "- **Threshold:** %d (1=Low, 2=Medium, 3=High, 4=Critical)\n", cfg.Threshold)
	fmt.Fprintf(&sb, "- **Correlation window:** %d seconds\n", cfg.WindowSecs)
	sb.WriteString("\nThe defense daemon hot-reloads this file every 5 seconds when started with `--config`.\n\n")
	sb.WriteString("```json\n")
	sb.Write(data)
	sb.WriteString("\n```\n")
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// parseRuntimeConfig decodes a RuntimeConfig JSON blob, applying the engine's
// serde defaults for missing fields and rejecting out-of-range values.
func parseRuntimeConfig(data []byte) (*runtimeConfig, error) {
	var raw struct {
		Threshold  *int `json:"threshold"`
		WindowSecs *int `json:"window_secs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %v", err)
	}
	cfg := &runtimeConfig{
		Threshold:  defaultConfigThreshold,
		WindowSecs: defaultConfigWindowSecs,
	}
	if raw.Threshold != nil {
		cfg.Threshold = *raw.Threshold
	}
	if raw.WindowSecs != nil {
		cfg.WindowSecs = *raw.WindowSecs
	}
	if err := validateThreshold(cfg.Threshold); err != nil {
		return nil, fmt.Errorf("invalid threshold in config: %v", err)
	}
	if cfg.WindowSecs < 1 || cfg.WindowSecs > maxConfigWindowSecs {
		return nil, fmt.Errorf("invalid window_secs in config: must be 1-%d", maxConfigWindowSecs)
	}
	return cfg, nil
}

// DefenseConfigWriteTool writes a defense runtime config file.
type DefenseConfigWriteTool struct{}

// NewDefenseConfigWrite constructs the aegis_defense_config_write tool.
func NewDefenseConfigWrite() *DefenseConfigWriteTool { return &DefenseConfigWriteTool{} }

func (t *DefenseConfigWriteTool) Name() string { return "aegis_defense_config_write" }

func (t *DefenseConfigWriteTool) Description() string {
	return "Write an Aegis-Shadow defense runtime config file ({\"threshold\":N,\"window_secs\":N}) with 0600 permissions, for use as `defense --config <path>` (hot-reloaded every 5s). Wraps Aegis-Shadow (Linux eBPF security research platform, educational/VM-only) for authorized lab use only. Writes one small JSON file; never executes any binary. Omitted values default to the engine defaults (threshold 2, window 30s)."
}

func (t *DefenseConfigWriteTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"path": {
				"type": "string",
				"description": "Path of the config JSON file to write"
			},
			"threshold": {
				"type": "integer",
				"description": "Minimum alert severity to emit: 1=Low, 2=Medium, 3=High, 4=Critical (default: 2)"
			},
			"window_secs": {
				"type": "integer",
				"description": "Attack-chain correlation window in seconds, 1-86400 (default: 30)"
			}
		},
		"required": ["path"]
	}`)
}

func (t *DefenseConfigWriteTool) Execute(_ context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input struct {
		Path       string `json:"path"`
		Threshold  int    `json:"threshold"`
		WindowSecs int    `json:"window_secs"`
	}
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}
	if err := validateWritablePath(input.Path, "path"); err != nil {
		return errorResult(err.Error()), nil
	}

	cfg := runtimeConfig{
		Threshold:  defaultConfigThreshold,
		WindowSecs: defaultConfigWindowSecs,
	}
	if input.Threshold != 0 {
		cfg.Threshold = input.Threshold
	}
	if input.WindowSecs != 0 {
		cfg.WindowSecs = input.WindowSecs
	}
	if err := validateThreshold(cfg.Threshold); err != nil {
		return errorResult(err.Error()), nil
	}
	if cfg.WindowSecs < 1 || cfg.WindowSecs > maxConfigWindowSecs {
		return errorResult(fmt.Sprintf("window_secs must be 1-%d", maxConfigWindowSecs)), nil
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		return errorResult(fmt.Sprintf("cannot encode config: %v", err)), nil
	}
	if err := os.WriteFile(input.Path, payload, configFilePerm); err != nil {
		return errorResult(fmt.Sprintf("cannot write config file: %v", err)), nil
	}
	// os.WriteFile does not change the mode of an existing file; enforce it.
	if err := os.Chmod(input.Path, configFilePerm); err != nil {
		return errorResult(fmt.Sprintf("cannot set config file permissions: %v", err)), nil
	}

	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow Defense Runtime Config Written\n\n")
	fmt.Fprintf(&sb, "- **Path:** `%s`\n", input.Path)
	fmt.Fprintf(&sb, "- **Threshold:** %d (1=Low, 2=Medium, 3=High, 4=Critical)\n", cfg.Threshold)
	fmt.Fprintf(&sb, "- **Correlation window:** %d seconds\n", cfg.WindowSecs)
	fmt.Fprintf(&sb, "- **Permissions:** 0600\n\n")
	sb.WriteString("```json\n")
	sb.Write(payload)
	sb.WriteString("\n```\n\n")
	fmt.Fprintf(&sb, "Start or restart the defense daemon with `--config %s`; it hot-reloads this file every 5 seconds.\n", input.Path)
	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
