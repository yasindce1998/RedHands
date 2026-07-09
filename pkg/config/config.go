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
	Transport      string
	SSEAddr        string
	WSAddr         string
	TCPAddr        string
	PluginsDir     string

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
		Timeout:        5 * time.Minute,
		MaxOutputBytes: 10 * 1024 * 1024,
		RateLimit:      10,
		RateBurst:      20,
		CacheTTL:       5 * time.Minute,
		CacheMaxSize:   100,
		AuditFile:      "audit.jsonl",
		Transport:      "stdio",
		SSEAddr:        ":8080",
		WSAddr:         ":8081",
		PluginsDir:     "./plugins",
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

	// Workflow
	cfg.WorkflowStateDir = envOr("REDHANDS_WORKFLOW_STATE_DIR", "workflow_state")
	cfg.WorkflowTemplateDir = envOr("REDHANDS_WORKFLOW_TEMPLATES_DIR", "workflow_templates")
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

	return cfg
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
