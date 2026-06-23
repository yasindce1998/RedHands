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
	"github.com/yasindce1998/redhands/tools/exploit/sqlmap"
	"github.com/yasindce1998/redhands/tools/fuzz/feroxbuster"
	"github.com/yasindce1998/redhands/tools/fuzz/ffuf"
	"github.com/yasindce1998/redhands/tools/fuzz/gobuster"
	"github.com/yasindce1998/redhands/tools/recon/amass"
	"github.com/yasindce1998/redhands/tools/recon/arjun"
	"github.com/yasindce1998/redhands/tools/recon/dns"
	"github.com/yasindce1998/redhands/tools/recon/gau"
	"github.com/yasindce1998/redhands/tools/recon/subfinder"
	"github.com/yasindce1998/redhands/tools/recon/wayback"
	nmaptools "github.com/yasindce1998/redhands/tools/scan/nmap"
	"github.com/yasindce1998/redhands/tools/scan/masscan"
	"github.com/yasindce1998/redhands/tools/scan/rustscan"
	"github.com/yasindce1998/redhands/tools/system/health"
	"github.com/yasindce1998/redhands/tools/vuln/nuclei"
	"github.com/yasindce1998/redhands/tools/web/httpx"
	"github.com/yasindce1998/redhands/tools/web/katana"
	"github.com/yasindce1998/redhands/tools/web/nikto"
	"github.com/yasindce1998/redhands/tools/web/testssl"
	"github.com/yasindce1998/redhands/tools/web/whatweb"
)

var allBinaries = []string{
	"nmap", "subfinder", "httpx", "nuclei", "ffuf",
	"dig", "amass", "katana", "nikto", "gobuster",
	"waybackurls", "testssl.sh", "whatweb", "sqlmap",
	"masscan", "rustscan", "feroxbuster", "arjun", "gau",
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

	srv := mcp.NewServer("redhands", "0.3.0")
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
		srv.RegisterTool(gau.NewGAU(execr))
		srv.RegisterTool(arjun.NewArjun(execr))
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
		srv.RegisterTool(feroxbuster.NewFeroxbuster(execr))
	}

	// Scanning toolset
	if cfg.ToolsetEnabled("scan") {
		srv.RegisterTool(masscan.NewMasscan(execr))
		srv.RegisterTool(rustscan.NewRustScan(execr))
	}

	// Exploit toolset
	if cfg.ToolsetEnabled("exploit") {
		srv.RegisterTool(sqlmap.NewSQLMap(execr))
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
