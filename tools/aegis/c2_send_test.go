package aegis

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

func c2Call(t *testing.T, tool *C2SendTool, params string) (*mcp.ToolResult, error) {
	t.Helper()
	return tool.Execute(context.Background(), json.RawMessage(params))
}

func TestC2SendSchemaAndContract(t *testing.T) {
	tool := NewC2Send(executor.NewMock())
	if tool.Name() != "aegis_c2_send" {
		t.Fatalf("name: %s", tool.Name())
	}
	var schema map[string]any
	if err := json.Unmarshal(tool.InputSchema(), &schema); err != nil {
		t.Fatalf("schema invalid: %v", err)
	}
	if !strings.Contains(tool.Description(), "authorized lab use only") {
		t.Error("description missing authorized-lab framing")
	}
	if !strings.Contains(tool.Description(), "fire-and-forget") {
		t.Error("description should document the no-ack semantics")
	}
}

func TestC2SendArgs(t *testing.T) {
	calls := executor.NewMock()
	tool := NewC2Send(calls)

	// Minimal call with defaults.
	if r, err := c2Call(t, tool, `{"target":"192.0.2.10","command":"exfil"}`); err != nil || r.IsError {
		t.Fatalf("exfil call failed: %v %+v", err, r)
	}
	call := calls.Calls[len(calls.Calls)-1]
	want := []string{"--target", "192.0.2.10", "--command", "exfil", "--port", "53"}
	if !equalArgs(call.Args, want) {
		t.Fatalf("args = %v, want %v", call.Args, want)
	}

	// hide-pid with arg, custom port, and key.
	if r, err := c2Call(t, tool, `{"target":"192.0.2.10","command":"hide-pid","arg":"1234","port":9999,"key":"`+strings.Repeat("ab", 32)+`"}`); err != nil || r.IsError {
		t.Fatalf("hide-pid call failed: %v %+v", err, r)
	}
	call = calls.Calls[len(calls.Calls)-1]
	want = []string{"--target", "192.0.2.10", "--command", "hide-pid", "--port", "9999", "--arg", "1234", "--key", strings.Repeat("ab", 32)}
	if !equalArgs(call.Args, want) {
		t.Fatalf("args = %v, want %v", call.Args, want)
	}
}

func equalArgs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestC2SendValidation(t *testing.T) {
	tool := NewC2Send(executor.NewMock())
	for _, tc := range []struct {
		name   string
		params string
		want   string
	}{
		{"missing target", `{"command":"exfil"}`, "target is required"},
		{"ipv6 rejected", `{"target":"::1","command":"exfil"}`, "IPv4"},
		{"hostname rejected", `{"target":"labhost","command":"exfil"}`, "IPv4"},
		{"bad command", `{"target":"192.0.2.1","command":"detonate"}`, "command must be one of"},
		{"missing arg", `{"target":"192.0.2.1","command":"hide-pid"}`, "requires arg"},
		{"non-numeric arg", `{"target":"192.0.2.1","command":"hide-pid","arg":"abc"}`, "positive integer"},
		{"zero arg", `{"target":"192.0.2.1","command":"unhide-pid","arg":"0"}`, "positive integer"},
		{"arg overflow", `{"target":"192.0.2.1","command":"obfuscate-file","arg":"4294967296"}`, "positive integer"},
		{"arg on exfil", `{"target":"192.0.2.1","command":"exfil","arg":"5"}`, "takes no arg"},
		{"arg on kill-switch", `{"target":"192.0.2.1","command":"kill-switch","arg":"5"}`, "takes no arg"},
		{"bad port", `{"target":"192.0.2.1","command":"exfil","port":-1}`, "port must be"},
		{"port overflow", `{"target":"192.0.2.1","command":"exfil","port":70000}`, "port must be"},
		{"short key", `{"target":"192.0.2.1","command":"exfil","key":"abcd"}`, "64 hexadecimal"},
		{"non-hex key", `{"target":"192.0.2.1","command":"exfil","key":"` + strings.Repeat("zz", 32) + `"}`, "64 hexadecimal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := c2Call(t, tool, tc.params)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !r.IsError {
				t.Fatalf("expected error result, got %+v", r)
			}
			if !strings.Contains(r.Content[0].Text, tc.want) {
				t.Fatalf("error %q missing %q", r.Content[0].Text, tc.want)
			}
		})
	}
}
