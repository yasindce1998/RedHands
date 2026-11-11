package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/png"
	"os"
	"strings"
	"testing"

	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/evidence"
	"github.com/yasindce1998/redhands/pkg/execution"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
)

func TestRegisteredScreenshotUsesSharedExecutorAndApproval(t *testing.T) {
	store, err := evidence.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	if err := png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	mock := executor.NewMock()
	mock.StdoutFn = func(binary string, args []string) []byte {
		if binary != "cutycapt" {
			t.Errorf("unexpected binary: %s", binary)
		}
		for _, arg := range args {
			if strings.HasPrefix(arg, "--out=") {
				if err := os.WriteFile(strings.TrimPrefix(arg, "--out="), data.Bytes(), 0600); err != nil {
					t.Error(err)
				}
			}
		}
		return nil
	}
	cfg := config.Load()
	cfg.Toolsets = []string{"reporting"}
	srv := mcp.NewServer("test", "1")
	RegisterAll(srv, &Deps{Exec: mock, Cfg: &cfg, TargetDB: targetdb.NewStore("", false), Evidence: store})
	srv.Use(execution.Approval(nil))
	args := json.RawMessage(`{"url":"https://example.test"}`)
	result, err := srv.ExecuteTool(context.Background(), "evidence_screenshot", args)
	if err != nil || !result.IsError || len(mock.Calls) != 0 {
		t.Fatal("screenshot approval was bypassed")
	}
	approved := mcp.NewServer("test", "1")
	RegisterAll(approved, &Deps{Exec: mock, Cfg: &cfg, TargetDB: targetdb.NewStore("", false), Evidence: store})
	approved.Use(execution.Approval([]string{"evidence_screenshot"}))
	result, err = approved.ExecuteTool(context.Background(), "evidence_screenshot", args)
	if err != nil || result.IsError {
		t.Fatalf("approved screenshot failed: %+v %v", result, err)
	}
	if len(mock.Calls) != 1 {
		t.Fatal("screenshot did not use injected executor")
	}
	reopened, err := evidence.NewStore(store.Dir())
	if err != nil || len(reopened.List()) != 1 {
		t.Fatalf("screenshot not restored: %v", err)
	}
}
