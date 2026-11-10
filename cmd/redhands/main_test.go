package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerProcess(t *testing.T) {
	if os.Getenv("REDHANDS_TEST_PROCESS") != "1" {
		return
	}
	main()
	os.Exit(0)
}

func TestStdioWorkflowDryRunProcess(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerProcess$")
	cmd.Dir = dir
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "REDHANDS_") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "REDHANDS_TEST_PROCESS=1", "REDHANDS_AUTH=none", "REDHANDS_DRY_RUN=true", "REDHANDS_TOOLSETS=targetdb")
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"workflow/run","params":{"steps":[{"tool":"targetdb_add_host","params":{"ip":"192.0.2.1"}}]}}` + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("server startup: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("DRY-RUN")) {
		t.Fatalf("dry-run missing: %s", output)
	}
	if _, err := os.Stat(filepath.Join(dir, "targetdb.json")); !os.IsNotExist(err) {
		t.Fatal("dry-run created database")
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(audit), &event); err != nil {
		t.Fatalf("invalid audit: %s: %v", audit, err)
	}
	if event["tool"] != "targetdb_add_host" {
		t.Fatalf("wrong audit event: %s", audit)
	}
}
