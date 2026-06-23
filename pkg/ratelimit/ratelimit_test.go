package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterAllow(t *testing.T) {
	limiter := New(10, 5)

	for i := range 5 {
		if !limiter.Allow() {
			t.Fatalf("expected allow on request %d", i)
		}
	}

	if limiter.Allow() {
		t.Fatal("expected deny after burst exhausted")
	}
}

func TestLimiterRefill(t *testing.T) {
	limiter := New(100, 5)

	for range 5 {
		limiter.Allow()
	}

	if limiter.Allow() {
		t.Fatal("expected deny")
	}

	time.Sleep(60 * time.Millisecond)

	if !limiter.Allow() {
		t.Fatal("expected allow after refill")
	}
}
