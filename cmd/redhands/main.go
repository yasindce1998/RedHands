package main

import (
	"context"
	"log"
	"os"
	"os/exec"

	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/cache"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/ratelimit"
	"github.com/yasindce1998/redhands/tools/amass"
	"github.com/yasindce1998/redhands/tools/dns"
	"github.com/yasindce1998/redhands/tools/ffuf"
	"github.com/yasindce1998/redhands/tools/gobuster"
	"github.com/yasindce1998/redhands/tools/health"
	"github.com/yasindce1998/redhands/tools/httpx"
	"github.com/yasindce1998/redhands/tools/katana"
	"github.com/yasindce1998/redhands/tools/nikto"
	nmaptools "github.com/yasindce1998/redhands/tools/nmap"
	"github.com/yasindce1998/redhands/tools/nuclei"
	"github.com/yasindce1998/redhands/tools/subfinder"
	"github.com/yasindce1998/redhands/tools/testssl"
	"github.com/yasindce1998/redhands/tools/wayback"
	"github.com/yasindce1998/redhands/tools/whatweb"
)

var allBinaries = []string{
	"nmap", "subfinder", "httpx", "nuclei", "ffuf",
	"dig", "amass", "katana", "nikto", "gobuster",
	"waybackurls", "testssl.sh", "whatweb",
}

func main() {
	log.SetOutput(os.Stderr)

	cfg := config.Load()

	binPaths := discoverBinaries()
	execr := executor.New(executor.Config{
		Timeout:         int64(cfg.Timeout.Seconds()),
		AllowedBinaries: binPaths,
		MaxOutputBytes:  cfg.MaxOutputBytes,
	})

	auditLogger, err := audit.NewFileLogger(cfg.AuditFile)
	if err != nil {
		log.Fatalf("failed to initialize audit logger: %v", err)
	}
	defer func() { _ = auditLogger.Close() }()

	limiter := ratelimit.New(cfg.RateLimit, cfg.RateBurst)
	resultCache := cache.New(cfg.CacheMaxSize, cfg.CacheTTL)

	srv := mcp.NewServer("redhands", "0.2.0")
	srv.Use(audit.Middleware(auditLogger))
	srv.Use(ratelimit.Middleware(limiter))
	srv.Use(cache.Middleware(resultCache))

	// Nmap toolset
	if cfg.ToolsetEnabled("nmap") {
		srv.RegisterTool(nmaptools.NewPortScan(execr))
		srv.RegisterTool(nmaptools.NewServiceDetect(execr))
		srv.RegisterTool(nmaptools.NewOSDetect(execr))
		srv.RegisterTool(nmaptools.NewVulnScan(execr))
	}

	// Recon toolset
	if cfg.ToolsetEnabled("recon") {
		srv.RegisterTool(subfinder.NewSubdomainEnum(execr))
		srv.RegisterTool(amass.NewASNEnum(execr))
		srv.RegisterTool(dns.NewDNSLookup(execr))
		srv.RegisterTool(wayback.NewWayback(execr))
	}

	// Web toolset
	if cfg.ToolsetEnabled("web") {
		srv.RegisterTool(httpx.NewHTTPProbe(execr))
		srv.RegisterTool(katana.NewCrawl(execr))
		srv.RegisterTool(nikto.NewWebScan(execr))
		srv.RegisterTool(whatweb.NewFingerprint(execr))
		srv.RegisterTool(testssl.NewTLSScan(execr))
	}

	// Fuzzing toolset
	if cfg.ToolsetEnabled("fuzz") {
		srv.RegisterTool(ffuf.NewWebFuzz(execr))
		srv.RegisterTool(gobuster.NewDirBust(execr))
	}

	// Vuln toolset
	if cfg.ToolsetEnabled("vuln") {
		srv.RegisterTool(nuclei.NewNucleiScan(execr))
	}

	// Health (always registered)
	srv.RegisterTool(health.NewHealthCheck(allBinaries))

	if err := srv.ServeStdio(context.Background()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func discoverBinaries() map[string]string {
	paths := make(map[string]string)
	for _, bin := range allBinaries {
		if p, err := exec.LookPath(bin); err == nil {
			paths[bin] = p
		}
	}
	return paths
}
