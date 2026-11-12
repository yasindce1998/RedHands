package config

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Toolsets        []string
	Timeout         time.Duration
	MaxOutputBytes  int64
	RateLimit       int
	RateBurst       int
	CacheTTL        time.Duration
	CacheMaxSize    int
	AuditFile       string
	Transport       string
	SSEAddr         string
	WSAddr          string
	TCPAddr         string
	PluginsDir      string
	MaxConcurrent   int
	MaxQueued       int
	ApprovedTools   []string
	WorkflowTimeout time.Duration

	// Target database
	TargetDBFile     string
	TargetDBAutoSave bool

	// OPSEC
	OpsecProfile string
	OpsecProxies []string
	IOCFile      string

	// Engagement
	EngagementDir string

	// Credential store
	CredStoreFile string
	CredStoreKey  string

	// Loot
	LootDir string

	// Notifications
	WebhookURLs   []string
	WebhookEvents []string

	// Multi-operator
	OperatorID string
	SyncPeers  []string

	// Evidence
	EvidenceDir string

	// Dashboard
	DashboardAddr string

	// Dry-run mode
	DryRun bool

	// Workflow
	WorkflowStateDir    string
	WorkflowTemplateDir string
	WorkflowMaxParallel int

	// Plugin watcher
	PluginPollInterval time.Duration
}

func Load() Config {
	cfg := Config{
		Timeout:         5 * time.Minute,
		MaxOutputBytes:  10 * 1024 * 1024,
		RateLimit:       10,
		RateBurst:       20,
		CacheTTL:        5 * time.Minute,
		CacheMaxSize:    100,
		AuditFile:       "audit.jsonl",
		Transport:       "stdio",
		SSEAddr:         "127.0.0.1:8080",
		WSAddr:          "127.0.0.1:8081",
		PluginsDir:      "./plugins",
		MaxConcurrent:   4,
		MaxQueued:       16,
		WorkflowTimeout: 30 * time.Minute,
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

	if v := os.Getenv("REDHANDS_TRANSPORT"); v != "" {
		cfg.Transport = v
	}

	if v := os.Getenv("REDHANDS_SSE_ADDR"); v != "" {
		cfg.SSEAddr = v
	}

	if v := os.Getenv("REDHANDS_WS_ADDR"); v != "" {
		cfg.WSAddr = v
	}

	if v := os.Getenv("REDHANDS_PLUGINS_DIR"); v != "" {
		cfg.PluginsDir = v
	}

	if v := os.Getenv("REDHANDS_TCP_ADDR"); v != "" {
		cfg.TCPAddr = v
	}

	// Target database
	cfg.TargetDBFile = envOr("REDHANDS_TARGETDB_FILE", "targetdb.json")
	cfg.TargetDBAutoSave = envOr("REDHANDS_TARGETDB_AUTOSAVE", "true") == "true"

	// OPSEC
	cfg.OpsecProfile = os.Getenv("REDHANDS_OPSEC_PROFILE")
	if v := os.Getenv("REDHANDS_OPSEC_PROXIES"); v != "" {
		cfg.OpsecProxies = strings.Split(v, ",")
	}
	cfg.IOCFile = os.Getenv("REDHANDS_IOC_FILE")

	// Engagement
	cfg.EngagementDir = envOr("REDHANDS_ENGAGEMENT_DIR", "engagements")

	// Credential store
	cfg.CredStoreFile = envOr("REDHANDS_CREDSTORE_FILE", "credstore.enc")
	cfg.CredStoreKey = os.Getenv("REDHANDS_CREDSTORE_KEY")

	// Loot
	cfg.LootDir = envOr("REDHANDS_LOOT_DIR", "loot")

	// Notifications
	if v := os.Getenv("REDHANDS_WEBHOOK_URLS"); v != "" {
		cfg.WebhookURLs = strings.Split(v, ",")
	}
	if v := os.Getenv("REDHANDS_WEBHOOK_EVENTS"); v != "" {
		cfg.WebhookEvents = strings.Split(v, ",")
	}

	// Multi-operator
	cfg.OperatorID = os.Getenv("REDHANDS_OPERATOR_ID")
	if v := os.Getenv("REDHANDS_SYNC_PEERS"); v != "" {
		cfg.SyncPeers = strings.Split(v, ",")
	}

	// Evidence
	cfg.EvidenceDir = envOr("REDHANDS_EVIDENCE_DIR", "evidence")

	// Dashboard
	cfg.DashboardAddr = os.Getenv("REDHANDS_DASHBOARD_ADDR")

	// Dry-run
	cfg.DryRun = os.Getenv("REDHANDS_DRY_RUN") == "true"

	// Workflow / campaign
	cfg.WorkflowStateDir = envOr("REDHANDS_WORKFLOW_STATE_DIR", "workflow_state")
	cfg.WorkflowTemplateDir = envOr("REDHANDS_WORKFLOW_TEMPLATES_DIR", "playbooks")
	if v := os.Getenv("REDHANDS_WORKFLOW_MAX_PARALLEL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.WorkflowMaxParallel = n
		}
	}
	if cfg.WorkflowMaxParallel == 0 {
		cfg.WorkflowMaxParallel = 4
	}

	// Plugin watcher
	cfg.PluginPollInterval = 5 * time.Second
	if v := os.Getenv("REDHANDS_PLUGIN_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PluginPollInterval = d
		}
	}
	if v := os.Getenv("REDHANDS_MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxConcurrent = n
		}
	}
	if v := os.Getenv("REDHANDS_MAX_QUEUED"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxQueued = n
		}
	}
	if v := os.Getenv("REDHANDS_APPROVED_TOOLS"); v != "" {
		for _, name := range strings.Split(v, ",") {
			cfg.ApprovedTools = append(cfg.ApprovedTools, strings.TrimSpace(name))
		}
	}
	if v := os.Getenv("REDHANDS_WORKFLOW_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.WorkflowTimeout = d
		}
	}

	return cfg
}

func (c Config) Validate() error {
	if c.Transport != "stdio" && c.Transport != "sse" && c.Transport != "ws" {
		return fmt.Errorf("unsupported transport %q", c.Transport)
	}
	if c.Timeout < time.Second || c.MaxOutputBytes <= 0 || c.RateLimit <= 0 || c.RateBurst <= 0 {
		return fmt.Errorf("timeout must be at least 1s; output and rate limits must be positive")
	}
	if c.CacheTTL < 0 || c.CacheMaxSize < 0 || c.PluginPollInterval <= 0 || c.WorkflowMaxParallel <= 0 {
		return fmt.Errorf("invalid cache, plugin polling or workflow limits")
	}
	if c.WorkflowMaxParallel > 32 {
		return fmt.Errorf("REDHANDS_WORKFLOW_MAX_PARALLEL must be at most 32")
	}
	if c.MaxConcurrent < 1 || c.MaxConcurrent > 256 || c.MaxQueued < 0 || c.MaxQueued > 4096 || c.WorkflowTimeout <= 0 {
		return fmt.Errorf("execution limits must be 1..256 concurrent, 0..4096 queued, and a positive workflow timeout")
	}
	for _, name := range c.ApprovedTools {
		if name == "" || strings.ContainsAny(name, "*? \t\r\n") {
			return fmt.Errorf("REDHANDS_APPROVED_TOOLS requires exact, non-empty tool names")
		}
	}
	// Load historically falls back on parse errors. Reject them before startup.
	for _, key := range []string{"REDHANDS_TIMEOUT", "REDHANDS_CACHE_TTL", "REDHANDS_PLUGIN_POLL_INTERVAL", "REDHANDS_WORKFLOW_TIMEOUT"} {
		if v := os.Getenv(key); v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	for _, key := range []string{"REDHANDS_MAX_OUTPUT", "REDHANDS_RATE_LIMIT", "REDHANDS_RATE_BURST", "REDHANDS_CACHE_SIZE", "REDHANDS_WORKFLOW_MAX_PARALLEL", "REDHANDS_MAX_CONCURRENT", "REDHANDS_MAX_QUEUED"} {
		if v := os.Getenv(key); v != "" {
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	// These knobs were parsed but never connected to the running server. Fail
	// explicitly rather than giving operators a false sense of configured behavior.
	for _, key := range []string{"REDHANDS_OPSEC_PROXIES", "REDHANDS_OPERATOR_ID", "REDHANDS_SYNC_PEERS", "REDHANDS_WEBHOOK_URLS", "REDHANDS_WEBHOOK_EVENTS"} {
		if os.Getenv(key) != "" {
			return fmt.Errorf("%s is not supported by the active server; unset it", key)
		}
	}
	for _, key := range []string{"REDHANDS_DRY_RUN", "REDHANDS_TARGETDB_AUTOSAVE"} {
		if value := os.Getenv(key); value != "" && value != "true" && value != "false" {
			return fmt.Errorf("%s must be true or false", key)
		}
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c Config) ToolsetEnabled(name string) bool {
	if len(c.Toolsets) == 0 {
		return true
	}
	return slices.Contains(c.Toolsets, name)
}
