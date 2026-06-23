package config

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Toolsets       []string
	Timeout        time.Duration
	MaxOutputBytes int64
	RateLimit      int
	RateBurst      int
	CacheTTL       time.Duration
	CacheMaxSize   int
	AuditFile      string
}

func Load() Config {
	cfg := Config{
		Timeout:        5 * time.Minute,
		MaxOutputBytes: 10 * 1024 * 1024,
		RateLimit:      10,
		RateBurst:      20,
		CacheTTL:       5 * time.Minute,
		CacheMaxSize:   100,
		AuditFile:      "audit.jsonl",
	}

	if v := os.Getenv("REDHANDS_TOOLSETS"); v != "" {
		cfg.Toolsets = strings.Split(v, ",")
		for i := range cfg.Toolsets {
			cfg.Toolsets[i] = strings.TrimSpace(cfg.Toolsets[i])
		}
	}

	if v := os.Getenv("REDHANDS_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Timeout = d
		}
	}

	if v := os.Getenv("REDHANDS_MAX_OUTPUT"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.MaxOutputBytes = n
		}
	}

	if v := os.Getenv("REDHANDS_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit = n
		}
	}

	if v := os.Getenv("REDHANDS_RATE_BURST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateBurst = n
		}
	}

	if v := os.Getenv("REDHANDS_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.CacheTTL = d
		}
	}

	if v := os.Getenv("REDHANDS_CACHE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CacheMaxSize = n
		}
	}

	if v := os.Getenv("REDHANDS_AUDIT_FILE"); v != "" {
		cfg.AuditFile = v
	}

	return cfg
}

func (c Config) ToolsetEnabled(name string) bool {
	if len(c.Toolsets) == 0 {
		return true
	}
	return slices.Contains(c.Toolsets, name)
}
