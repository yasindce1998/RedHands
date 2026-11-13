//go:build unix

package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

// TestCampaignSingleWriter verifies the per-campaign run lock: while one
// goroutine executes a campaign, a second start (and a resume) with the same
// workflow ID fails with ErrAlreadyRunning instead of silently replacing the
// running entry. This file is unix-only because the cross-process lock is
// flock-based; on other platforms the in-process running map is the only
// guard.
func TestCampaignSingleWriter(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			started <- struct{}{}
			select {
			case <-ctx.Done():
				return "", false, ctx.Err()
			case <-release:
			}
		}
		return "ok", true, nil
	}
	engine, _ := newTestEngine(t, exec)

	var (
		runResult *WorkflowResult
		runErr    error
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runResult, runErr = engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
			ID: "single-writer",
			Steps: []EnhancedStep{
				{ID: "hang", Tool: "hang"},
				{ID: "after", Tool: "after"},
			},
		})
	}()

	<-started // the first run holds the lock and is mid-step.

	// A second start with the same ID is rejected, not silently replacing
	// the running campaign.
	_, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
		ID:    "single-writer",
		Steps: []EnhancedStep{{ID: "hang", Tool: "hang"}},
	})
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second start should fail with ErrAlreadyRunning, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "campaign single-writer") {
		t.Fatalf("error should name the campaign, got %v", err)
	}

	// Resuming the running campaign is also rejected.
	_, err = engine.Resume(context.Background(), "single-writer")
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("resume while running should fail with ErrAlreadyRunning, got %v", err)
	}

	// The rejected start must not have disturbed the running campaign's
	// state (the first run still owns its checkpoint file).
	state, err := engine.Status("single-writer")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if state.Status != "running" || state.WorkflowID != "single-writer" {
		t.Fatalf("running campaign state disturbed: %+v", state)
	}

	close(release)
	<-done

	if runErr != nil || runResult == nil || !runResult.Success {
		t.Fatalf("first run should complete: result=%+v err=%v", runResult, runErr)
	}
}
