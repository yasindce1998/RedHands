package audit

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentCloseAndLog(t *testing.T) {
	logger, err := NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				_ = logger.Log(context.Background(), AuditEvent{Tool: "test"})
			}
		})
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(context.Background(), AuditEvent{}); err == nil {
		t.Fatal("log after close accepted")
	}
}
