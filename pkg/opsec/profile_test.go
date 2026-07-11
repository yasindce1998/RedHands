package opsec

import (
	"testing"
	"time"
)

func TestGetProfile_Known(t *testing.T) {
	tests := []struct {
		name     string
		minDelay time.Duration
	}{
		{"stealth", 5 * time.Second},
		{"normal", 500 * time.Millisecond},
		{"loud", 0},
	}
	for _, tc := range tests {
		p := GetProfile(tc.name)
		if p.Name != tc.name {
			t.Errorf("GetProfile(%q).Name = %q", tc.name, p.Name)
		}
		if p.MinDelay != tc.minDelay {
			t.Errorf("GetProfile(%q).MinDelay = %v, want %v", tc.name, p.MinDelay, tc.minDelay)
		}
	}
}

func TestGetProfile_Unknown_DefaultsToNormal(t *testing.T) {
	p := GetProfile("nonexistent")
	if p.Name != "normal" {
		t.Errorf("unknown profile should default to normal, got %q", p.Name)
	}
}

func TestProfiles_StealthConstraints(t *testing.T) {
	p := Profiles["stealth"]
	if p.MaxPerMinute != 2 {
		t.Errorf("stealth MaxPerMinute = %d, want 2", p.MaxPerMinute)
	}
	if p.MaxPerTarget != 1 {
		t.Errorf("stealth MaxPerTarget = %d, want 1", p.MaxPerTarget)
	}
	if p.JitterPct != 0.5 {
		t.Errorf("stealth JitterPct = %f, want 0.5", p.JitterPct)
	}
}

func TestProfiles_LoudNoLimits(t *testing.T) {
	p := Profiles["loud"]
	if p.MaxPerMinute != 0 || p.MaxPerTarget != 0 || p.MaxDelay != 0 {
		t.Error("loud profile should have zero limits")
	}
}
