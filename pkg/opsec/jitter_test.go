package opsec

import (
	"testing"
	"time"
)

func TestJitter_ZeroMax(t *testing.T) {
	d := Jitter(0, 0, 0.5)
	if d != 0 {
		t.Errorf("Jitter(0,0,0.5) = %v, want 0", d)
	}
}

func TestJitter_MinEqualsMax(t *testing.T) {
	d := Jitter(5*time.Second, 5*time.Second, 0.5)
	if d != 5*time.Second {
		t.Errorf("Jitter(5s,5s,0.5) = %v, want 5s", d)
	}
}

func TestJitter_MinGreaterThanMax(t *testing.T) {
	d := Jitter(10*time.Second, 5*time.Second, 0.5)
	if d != 10*time.Second {
		t.Errorf("Jitter(10s,5s) = %v, want 10s (min)", d)
	}
}

func TestJitter_WithinRange(t *testing.T) {
	min := 100 * time.Millisecond
	max := 500 * time.Millisecond

	for i := 0; i < 100; i++ {
		d := Jitter(min, max, 0.5)
		if d < min || d > max {
			t.Errorf("Jitter out of range: %v (min=%v, max=%v)", d, min, max)
		}
	}
}

func TestSleep_ZeroDuration(t *testing.T) {
	done := make(chan struct{})
	Sleep(0, 0, 0.5, done)
}

func TestSleep_Cancelled(t *testing.T) {
	done := make(chan struct{})
	close(done)

	start := time.Now()
	Sleep(1*time.Second, 5*time.Second, 0.5, done)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("Sleep should return immediately on closed done channel, took %v", elapsed)
	}
}
