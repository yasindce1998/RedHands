package kubedagger

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/workflow"
)

// Golden pipeline tests against the KubeDagger discovery output shape.
//
// testdata/kubedagger/cluster-report.json is derived strictly from the
// ClusterReport struct that `kubedagger-client k8s discover` prints via
// json.MarshalIndent + fmt.Println (cmd/kubedagger-client/run/k8s/discovery.go),
// and testdata/kubedagger/k8s-discover-no-kubeconfig.stderr is a real capture
// of the binary failing without a kubeconfig. See the README there.
//
// These tests verify the full pipeline the k8s-recon-chain playbook depends
// on: fixture stdout → wrapper markdown fence → campaign structured
// extraction → record-rule field paths (nodes[].ip/name/os, pods[].pod_ip/
// name).

func loadGoldenFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "kubedagger", name))
	if err != nil {
		t.Fatalf("reading golden fixture: %v", err)
	}
	return data
}

func mustDecodeValue(t *testing.T, raw []byte) any {
	t.Helper()
	var value any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("decoding fixture JSON: %v", err)
	}
	return value
}

// TestK8sDiscoverGolden_JSONFencedForCampaignExtraction feeds the
// ClusterReport stdout through the wrapper and asserts the output is fenced
// as ```json so workflow.StructuredFromText can extract it. Before this was
// fixed the wrapper used a plain ``` fence, which made the k8s-recon-chain
// record rules (paths "nodes"/"pods") and ${discover.json...} references
// unresolvable against the real binary output.
func TestK8sDiscoverGolden_JSONFencedForCampaignExtraction(t *testing.T) {
	report := loadGoldenFixture(t, "cluster-report.json")
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte { return report }
	tool := NewK8sDiscover(mock)

	result, err := tool.Execute(context.Background(), mustJSONGolden(map[string]any{"namespace": "default"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("discovery must be a result, not an error: %s", result.Content[0].Text)
	}

	text := result.Content[0].Text
	if !strings.Contains(text, "```json\n") {
		t.Fatalf("ClusterReport stdout not fenced as json; campaign extraction cannot see it:\n%s", text)
	}
	if !strings.Contains(text, "Namespace: default") {
		t.Errorf("namespace header missing:\n%s", text)
	}

	raw, ok := workflow.StructuredFromText(text)
	if !ok {
		t.Fatal("campaign extractor could not pull the ClusterReport out of the wrapper markdown")
	}
	value := mustDecodeValue(t, raw)
	for _, path := range []string{
		"nodes", "pods", "services", "namespaces", "targets",
		"nodes.0.name", "nodes.0.ip", "nodes.0.os", "nodes.0.kernel", "nodes.0.kubelet", "nodes.0.conditions",
		"pods.0.name", "pods.0.namespace", "pods.0.node_name", "pods.0.pod_ip", "pods.0.image",
		"pods.1.privileged", "pods.1.host_pid", "pods.1.host_network",
		"services.0.cluster_ip", "services.0.ports",
		"targets.0.type", "targets.0.reason",
	} {
		if _, ok := workflow.LookupPathValue(value, path); !ok {
			t.Errorf("path %q does not resolve against the ClusterReport shape (record rules / dataflow would break)", path)
		}
	}
}

// TestK8sDiscoverGolden_RecordRuleFieldsResolveForEveryItem checks the exact
// field mappings the k8s-recon-chain playbook record rules use —
// nodes: {ip: ip, hostname: name, os: os} and pods: {ip: pod_ip,
// hostname: name} — against every element of the fixture arrays, not just
// the first. This is the "wrapper says hosts.0.ip but the binary emits
// addresses[0]" class of bug.
func TestK8sDiscoverGolden_RecordRuleFieldsResolveForEveryItem(t *testing.T) {
	report := loadGoldenFixture(t, "cluster-report.json")
	value := mustDecodeValue(t, report)

	nodes, ok := workflow.LookupPathValue(value, "nodes")
	if !ok {
		t.Fatal("path \"nodes\" does not resolve")
	}
	nodeList, ok := nodes.([]any)
	if !ok {
		t.Fatalf("\"nodes\" is not an array: %T", nodes)
	}
	for i, node := range nodeList {
		fields := []string{"ip", "name", "os"}
		for _, field := range fields {
			if _, ok := workflow.LookupPathValue(node, field); !ok {
				t.Errorf("nodes.%d is missing field %q used by the k8s-recon-chain record rule", i, field)
			}
		}
	}

	pods, ok := workflow.LookupPathValue(value, "pods")
	if !ok {
		t.Fatal("path \"pods\" does not resolve")
	}
	podList, ok := pods.([]any)
	if !ok {
		t.Fatalf("\"pods\" is not an array: %T", pods)
	}
	for i, pod := range podList {
		for _, field := range []string{"pod_ip", "name"} {
			if _, ok := workflow.LookupPathValue(pod, field); !ok {
				t.Errorf("pods.%d is missing field %q used by the k8s-recon-chain record rule", i, field)
			}
		}
	}
}

// TestK8sDiscoverGolden_NonJSONOutputStaysPlainText pins the fallback: when
// the daemon emits non-JSON text (e.g. a table or log lines), the wrapper
// keeps the plain ``` fence instead of claiming JSON.
func TestK8sDiscoverGolden_NonJSONOutputStaysPlainText(t *testing.T) {
	mock := executor.NewMock()
	mock.StdoutFn = func(_ string, _ []string) []byte {
		return []byte("NAME          READY  STATUS\nnginx-pod-1   1/1    Running\n")
	}
	tool := NewK8sDiscover(mock)

	result, err := tool.Execute(context.Background(), mustJSONGolden(map[string]any{}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	text := result.Content[0].Text
	if strings.Contains(text, "```json") {
		t.Errorf("non-JSON output must not be fenced as json:\n%s", text)
	}
	if !strings.Contains(text, "nginx-pod-1") {
		t.Errorf("plain output not passed through:\n%s", text)
	}
}

// TestK8sDiscoverGolden_EmptyStdoutExitZeroIsTheRealFailureShape documents a
// real quirk of the kubedagger-client binary: with no kubeconfig/daemon it
// exits 0 with empty stdout and prints "Error: ..." to stderr (real capture
// in testdata/kubedagger/k8s-discover-no-kubeconfig.stderr). The wrapper
// keys failure off the exit code, so this real failure currently surfaces as
// a successful "No resources found." result. The test pins that behavior so
// any change (wrapper checking stderr, or the binary fixing its exit code)
// is a conscious one.
func TestK8sDiscoverGolden_EmptyStdoutExitZeroIsTheRealFailureShape(t *testing.T) {
	stderr := loadGoldenFixture(t, "k8s-discover-no-kubeconfig.stderr")
	mock := executor.NewMock()
	mock.StderrFn = func(_ string, _ []string) []byte { return stderr }
	// StdoutFn unset: real binary produced zero bytes of stdout here.
	tool := NewK8sDiscover(mock)

	result, err := tool.Execute(context.Background(), mustJSONGolden(map[string]any{"namespace": "default"}))
	if err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}
	if result.IsError {
		t.Fatalf("binary exits 0, so the wrapper must produce a result (documented drift): %s", result.Content[0].Text)
	}
	if !strings.Contains(result.Content[0].Text, "No resources found.") {
		t.Errorf("empty-stdout result shape changed; re-check the real binary failure mode:\n%s", result.Content[0].Text)
	}
	if !strings.Contains(string(stderr), "Error: k8s client init failed") {
		t.Errorf("real failure fixture no longer carries the k8s client init error")
	}
}

func mustJSONGolden(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
