package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestCampaignEngagementBinding(t *testing.T) {
	exec := func(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
		return "ok", true, nil
	}

	t.Run("unbound campaign skips the check", func(t *testing.T) {
		engine, _ := newTestEngine(t, exec)
		called := false
		engine.SetEngagementCheck(func(name string) error { called = true; return nil })
		if _, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
			Steps: []EnhancedStep{{Tool: "t"}},
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if called {
			t.Fatal("engagement check must not run for unbound campaigns")
		}
	})

	t.Run("bound campaign validates and persists the binding", func(t *testing.T) {
		engine, _ := newTestEngine(t, exec)
		engine.SetEngagementCheck(func(name string) error {
			if name != "lab-1" {
				return fmt.Errorf("unknown engagement %q", name)
			}
			return nil
		})
		result, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
			ID:         "bound-1",
			Engagement: "lab-1",
			Steps:      []EnhancedStep{{Tool: "t"}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Success {
			t.Fatalf("campaign failed: %+v", result)
		}
		state, err := engine.Status("bound-1")
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if state.Engagement != "lab-1" {
			t.Fatalf("engagement not persisted in state: %+v", state)
		}
	})

	t.Run("rejected binding fails before any step", func(t *testing.T) {
		engine, _ := newTestEngine(t, exec)
		engine.SetEngagementCheck(func(name string) error {
			return fmt.Errorf("engagement %q is not active", name)
		})
		if _, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
			Engagement: "other",
			Steps:      []EnhancedStep{{Tool: "t"}},
		}); err == nil {
			t.Fatal("expected engagement rejection")
		}
	})

	t.Run("binding without a configured check errors clearly", func(t *testing.T) {
		engine, _ := newTestEngine(t, exec)
		if _, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
			Engagement: "lab-1",
			Steps:      []EnhancedStep{{Tool: "t"}},
		}); err == nil {
			t.Fatal("expected missing-engagement-check error")
		}
	})

	t.Run("resume revalidates the binding", func(t *testing.T) {
		engine, _ := newTestEngine(t, exec)
		var active string
		engine.SetEngagementCheck(func(name string) error {
			if name != active {
				return fmt.Errorf("engagement %q is not active", name)
			}
			return nil
		})
		active = "lab-1"
		if _, err := engine.RunEnhanced(context.Background(), &EnhancedWorkflowRequest{
			ID:         "resume-eng",
			Engagement: "lab-1",
			Steps:      []EnhancedStep{{Tool: "t"}},
		}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Simulate the operator switching engagements between runs: mark
		// the completed campaign resumable, then flip the active engagement.
		state, err := engine.Status("resume-eng")
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		state.Status = "paused"
		if err := engine.state.Save(state); err != nil {
			t.Fatalf("save state: %v", err)
		}
		active = "other-engagement"
		if _, err := engine.Resume(context.Background(), "resume-eng"); err == nil {
			t.Fatal("expected resume to reject a stale engagement binding")
		}
	})
}
