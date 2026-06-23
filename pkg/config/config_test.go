package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Load()
	if cfg.Timeout != 5*time.Minute {
		t.Errorf("expected 5m timeout, got %v", cfg.Timeout)
	}
	if cfg.RateLimit != 10 {
		t.Errorf("expected rate limit 10, got %d", cfg.RateLimit)
	}
	if cfg.CacheMaxSize != 100 {
		t.Errorf("expected cache size 100, got %d", cfg.CacheMaxSize)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("REDHANDS_TOOLSETS", "nmap,nuclei,subfinder")
	t.Setenv("REDHANDS_TIMEOUT", "10m")
	t.Setenv("REDHANDS_RATE_LIMIT", "5")

	cfg := Load()
	if len(cfg.Toolsets) != 3 {
		t.Fatalf("expected 3 toolsets, got %d", len(cfg.Toolsets))
	}
	if cfg.Toolsets[0] != "nmap" || cfg.Toolsets[1] != "nuclei" || cfg.Toolsets[2] != "subfinder" {
		t.Errorf("unexpected toolsets: %v", cfg.Toolsets)
	}
	if cfg.Timeout != 10*time.Minute {
		t.Errorf("expected 10m timeout, got %v", cfg.Timeout)
	}
	if cfg.RateLimit != 5 {
		t.Errorf("expected rate limit 5, got %d", cfg.RateLimit)
	}
}

func TestToolsetEnabled(t *testing.T) {
	cfg := Config{Toolsets: []string{"nmap", "nuclei"}}
	if !cfg.ToolsetEnabled("nmap") {
		t.Error("nmap should be enabled")
	}
	if !cfg.ToolsetEnabled("nuclei") {
		t.Error("nuclei should be enabled")
	}
	if cfg.ToolsetEnabled("subfinder") {
		t.Error("subfinder should not be enabled")
	}

	cfgAll := Config{}
	if !cfgAll.ToolsetEnabled("anything") {
		t.Error("empty toolsets means all enabled")
	}
}
