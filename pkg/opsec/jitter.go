package opsec

import (
	"crypto/rand"
	"math/big"
	"time"
)

// Jitter calculates a random delay between min and max with jitter percentage applied.
func Jitter(min, max time.Duration, jitterPct float64) time.Duration {
	if max <= 0 {
		return 0
	}
	if min >= max {
		return min
	}

	rangeMs := max.Milliseconds() - min.Milliseconds()
	jitterRange := int64(float64(rangeMs) * jitterPct)
	if jitterRange <= 0 {
		jitterRange = rangeMs
	}

	n, err := rand.Int(rand.Reader, big.NewInt(jitterRange))
	if err != nil {
		return min
	}

	base := min.Milliseconds() + (rangeMs-jitterRange)/2
	return time.Duration(base+n.Int64()) * time.Millisecond
}

// Sleep pauses for a jittered duration. Returns immediately if context is done.
func Sleep(min, max time.Duration, jitterPct float64, done <-chan struct{}) {
	d := Jitter(min, max, jitterPct)
	if d <= 0 {
		return
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-done:
	}
}
