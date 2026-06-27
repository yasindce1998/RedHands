package ligolo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// ProxyStart tool

type ProxyStartInput struct {
	ListenAddr string `json:"listen_addr,omitempty"`
	Selfcert   bool   `json:"selfcert,omitempty"`
	Certfile   string `json:"certfile,omitempty"`
	Keyfile    string `json:"keyfile,omitempty"`
}

type ProxyStartTool struct {
	exec executor.Executor
}

func NewProxyStart(exec executor.Executor) *ProxyStartTool {
	return &ProxyStartTool{exec: exec}
}

func (t *ProxyStartTool) Name() string { return "ligolo_start" }

func (t *ProxyStartTool) Description() string {
	return "Start the Ligolo-ng proxy server. Waits for agent connections to establish tunnels through compromised hosts."
}

func (t *ProxyStartTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"listen_addr": {
				"type": "string",
				"description": "Listen address (default: 0.0.0.0:11601)"
			},
			"selfcert": {
				"type": "boolean",
				"description": "Use self-signed certificate"
			},
			"certfile": {
				"type": "string",
				"description": "Path to TLS certificate"
			},
			"keyfile": {
				"type": "string",
				"description": "Path to TLS key"
			}
		}
	}`)
}

func (t *ProxyStartTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ProxyStartInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.ListenAddr, "listen_addr"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Certfile, "certfile"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Keyfile, "keyfile"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{}
	if input.ListenAddr != "" {
		args = append(args, "-laddr", input.ListenAddr)
	}
	if input.Selfcert {
		args = append(args, "-selfcert")
	}
	if input.Certfile != "" {
		args = append(args, "-certfile", input.Certfile)
	}
	if input.Keyfile != "" {
		args = append(args, "-keyfile", input.Keyfile)
	}

	result, err := t.exec.Run(ctx, "ligolo-proxy", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("ligolo-proxy failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## Ligolo Proxy\n\n")
	if input.ListenAddr != "" {
		fmt.Fprintf(&sb, "**Listen**: %s\n\n", input.ListenAddr)
	}
	if output == "" {
		sb.WriteString("Proxy started, awaiting agents.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Route tool

type RouteInput struct {
	Action  string `json:"action"`
	Network string `json:"network,omitempty"`
	Name    string `json:"name,omitempty"`
}

type RouteTool struct {
	exec executor.Executor
}

func NewRoute(exec executor.Executor) *RouteTool {
	return &RouteTool{exec: exec}
}

func (t *RouteTool) Name() string { return "ligolo_route" }

func (t *RouteTool) Description() string {
	return "Manage routes through Ligolo tunnels. Add or remove network routes to access remote subnets through the tunnel interface."
}

func (t *RouteTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["add", "del", "list"],
				"description": "Route action"
			},
			"network": {
				"type": "string",
				"description": "Network CIDR (e.g., 10.0.0.0/24)"
			},
			"name": {
				"type": "string",
				"description": "Tunnel interface name"
			}
		},
		"required": ["action"]
	}`)
}

func (t *RouteTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input RouteInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Network, "network"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Name, "name"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "add":
		if input.Network == "" {
			return errorResult("network is required for add action"), nil
		}
		args = []string{"route_add", "--name", input.Name, input.Network}
		if input.Name == "" {
			args = []string{"route_add", input.Network}
		}
	case "del":
		if input.Network == "" {
			return errorResult("network is required for del action"), nil
		}
		args = []string{"route_del", input.Network}
	case "list":
		args = []string{"route_list"}
	default:
		return errorResult("invalid action: " + input.Action), nil
	}

	result, err := t.exec.Run(ctx, "ligolo-proxy", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("ligolo route failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Ligolo Route: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Route operation completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Listener tool

type ListenerInput struct {
	Action string `json:"action"`
	Addr   string `json:"addr,omitempty"`
	To     string `json:"to,omitempty"`
}

type ListenerTool struct {
	exec executor.Executor
}

func NewListener(exec executor.Executor) *ListenerTool {
	return &ListenerTool{exec: exec}
}

func (t *ListenerTool) Name() string { return "ligolo_listener" }

func (t *ListenerTool) Description() string {
	return "Manage Ligolo listeners on agent side. Create redirect listeners to receive reverse connections through the tunnel."
}

func (t *ListenerTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["add", "list"],
				"description": "Listener action"
			},
			"addr": {
				"type": "string",
				"description": "Listen address on agent (e.g., 0.0.0.0:4444)"
			},
			"to": {
				"type": "string",
				"description": "Redirect to address (e.g., 127.0.0.1:4444)"
			}
		},
		"required": ["action"]
	}`)
}

func (t *ListenerTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ListenerInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Addr, "addr"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.To, "to"); err != nil {
		return errorResult(err.Error()), nil
	}

	var args []string
	switch input.Action {
	case "add":
		if input.Addr == "" {
			return errorResult("addr is required for add action"), nil
		}
		if input.To == "" {
			return errorResult("to is required for add action"), nil
		}
		args = []string{"listener_add", "--addr", input.Addr, "--to", input.To}
	case "list":
		args = []string{"listener_list"}
	default:
		return errorResult("invalid action: " + input.Action), nil
	}

	result, err := t.exec.Run(ctx, "ligolo-proxy", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("ligolo listener failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## Ligolo Listener: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Listener operation completed.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
