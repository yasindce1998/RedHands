package opsec

import "time"

// Profile defines OPSEC behavior parameters.
type Profile struct {
	Name         string
	MinDelay     time.Duration
	MaxDelay     time.Duration
	MaxPerMinute int
	MaxPerTarget int
	JitterPct    float64
}

var Profiles = map[string]*Profile{
	"stealth": {
		Name:         "stealth",
		MinDelay:     5 * time.Second,
		MaxDelay:     30 * time.Second,
		MaxPerMinute: 2,
		MaxPerTarget: 1,
		JitterPct:    0.5,
	},
	"normal": {
		Name:         "normal",
		MinDelay:     500 * time.Millisecond,
		MaxDelay:     2 * time.Second,
		MaxPerMinute: 10,
		MaxPerTarget: 5,
		JitterPct:    0.2,
	},
	"loud": {
		Name:         "loud",
		MinDelay:     0,
		MaxDelay:     0,
		MaxPerMinute: 0,
		MaxPerTarget: 0,
		JitterPct:    0,
	},
}

// GetProfile returns the named profile, defaulting to "normal".
func GetProfile(name string) *Profile {
	if p, ok := Profiles[name]; ok {
		return p
	}
	return Profiles["normal"]
}
