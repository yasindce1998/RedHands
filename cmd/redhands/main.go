package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/cache"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/plugin"
	"github.com/yasindce1998/redhands/pkg/ratelimit"
	"github.com/yasindce1998/redhands/pkg/report"
	"github.com/yasindce1998/redhands/pkg/workflow"
	"github.com/yasindce1998/redhands/tools/analysis/tshark"
	"github.com/yasindce1998/redhands/tools/c2/sliver"
	"github.com/yasindce1998/redhands/tools/crack/hashcat"
	"github.com/yasindce1998/redhands/tools/crack/john"
	"github.com/yasindce1998/redhands/tools/exploit/certipy"
	"github.com/yasindce1998/redhands/tools/exploit/crackmapexec"
	"github.com/yasindce1998/redhands/tools/exploit/impacket"
	"github.com/yasindce1998/redhands/tools/exploit/sqlmap"
	"github.com/yasindce1998/redhands/tools/fuzz/feroxbuster"
	"github.com/yasindce1998/redhands/tools/fuzz/ffuf"
	"github.com/yasindce1998/redhands/tools/fuzz/gobuster"
	"github.com/yasindce1998/redhands/tools/barzakh"
	"github.com/yasindce1998/redhands/tools/kubedagger"
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
	"github.com/yasindce1998/redhands/tools/tunnel/chisel"
	"github.com/yasindce1998/redhands/tools/tunnel/ligolo"
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
	"kubedagger-client", "kubedagger-operator",
	// Impacket
	"impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
	"impacket-smbclient", "impacket-dcomexec", "impacket-getTGT",
	"impacket-getST", "impacket-ntlmrelayx",
	// Sliver C2
	"sliver-client",
	// Chisel / Ligolo
	"chisel", "ligolo-proxy",
	// Hashcat / John
	"hashcat", "john",
	// CrackMapExec
	"crackmapexec",
	// Certipy
	"certipy",
	// tshark
	"tshark",
	// Barzakh UEFI adversary toolkit
	"barzakh-adversary",
	"barzakh-scanner",
}

func main() {
	log.SetOutput(os.Stderr)

	cfg := config.Load()
	authCfg := auth.LoadConfig()

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

	srv := mcp.NewServer("redhands", "0.1.0")
	srv.Use(audit.Middleware(auditLogger))
	srv.Use(ratelimit.Middleware(limiter))
	srv.Use(cache.Middleware(resultCache))

	if authCfg.Mode != "none" {
		srv.Use(auth.Middleware(authCfg))
	}

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

	// Impacket toolset
	if cfg.ToolsetEnabled("impacket") {
		srv.RegisterTool(impacket.NewSecretsDump(execr))
		srv.RegisterTool(impacket.NewPsExec(execr))
		srv.RegisterTool(impacket.NewWmiExec(execr))
		srv.RegisterTool(impacket.NewSMBClient(execr))
		srv.RegisterTool(impacket.NewDcomExec(execr))
		srv.RegisterTool(impacket.NewGetTGT(execr))
		srv.RegisterTool(impacket.NewGetST(execr))
		srv.RegisterTool(impacket.NewNTLMRelay(execr))
	}

	// Sliver C2 toolset
	if cfg.ToolsetEnabled("sliver") {
		srv.RegisterTool(sliver.NewGenerate(execr))
		srv.RegisterTool(sliver.NewListeners(execr))
		srv.RegisterTool(sliver.NewSessions(execr))
		srv.RegisterTool(sliver.NewBeacons(execr))
		srv.RegisterTool(sliver.NewExecute(execr))
		srv.RegisterTool(sliver.NewUpload(execr))
		srv.RegisterTool(sliver.NewDownload(execr))
		srv.RegisterTool(sliver.NewPivot(execr))
		srv.RegisterTool(sliver.NewPortFwd(execr))
	}

	// Chisel/Ligolo tunneling toolset
	if cfg.ToolsetEnabled("tunnel") {
		srv.RegisterTool(chisel.NewServer(execr))
		srv.RegisterTool(chisel.NewClient(execr))
		srv.RegisterTool(ligolo.NewProxyStart(execr))
		srv.RegisterTool(ligolo.NewRoute(execr))
		srv.RegisterTool(ligolo.NewListener(execr))
	}

	// Hashcat/John cracking toolset
	if cfg.ToolsetEnabled("crack") {
		srv.RegisterTool(hashcat.NewCrack(execr))
		srv.RegisterTool(hashcat.NewBenchmark(execr))
		srv.RegisterTool(hashcat.NewShow(execr))
		srv.RegisterTool(john.NewCrack(execr))
		srv.RegisterTool(john.NewShow(execr))
		srv.RegisterTool(john.NewFormats(execr))
	}

	// CrackMapExec toolset
	if cfg.ToolsetEnabled("crackmapexec") {
		srv.RegisterTool(crackmapexec.NewSMB(execr))
		srv.RegisterTool(crackmapexec.NewWinRM(execr))
		srv.RegisterTool(crackmapexec.NewLDAP(execr))
		srv.RegisterTool(crackmapexec.NewMSSQL(execr))
		srv.RegisterTool(crackmapexec.NewSSH(execr))
	}

	// Certipy toolset
	if cfg.ToolsetEnabled("certipy") {
		srv.RegisterTool(certipy.NewFind(execr))
		srv.RegisterTool(certipy.NewRequest(execr))
		srv.RegisterTool(certipy.NewAuth(execr))
		srv.RegisterTool(certipy.NewShadow(execr))
		srv.RegisterTool(certipy.NewForge(execr))
		srv.RegisterTool(certipy.NewRelay(execr))
	}

	// tshark toolset
	if cfg.ToolsetEnabled("tshark") {
		srv.RegisterTool(tshark.NewCapture(execr))
		srv.RegisterTool(tshark.NewRead(execr))
		srv.RegisterTool(tshark.NewStats(execr))
		srv.RegisterTool(tshark.NewExtract(execr))
		srv.RegisterTool(tshark.NewFollow(execr))
	}

	// KubeDagger toolset
	if cfg.ToolsetEnabled("kubedagger") {
		srv.RegisterTool(kubedagger.NewNetworkScan(execr))
		srv.RegisterTool(kubedagger.NewNetworkDiscovery(execr))
		srv.RegisterTool(kubedagger.NewDockerList(execr))
		srv.RegisterTool(kubedagger.NewDockerOverride(execr))
		srv.RegisterTool(kubedagger.NewK8sDiscover(execr))
		srv.RegisterTool(kubedagger.NewK8sAbuse(execr))
		srv.RegisterTool(kubedagger.NewContainerEscape(execr))
		srv.RegisterTool(kubedagger.NewSecretsHarvest(execr))
		srv.RegisterTool(kubedagger.NewCloudMeta(execr))
		srv.RegisterTool(kubedagger.NewCloudExfil(execr))
		srv.RegisterTool(kubedagger.NewEvasion(execr))
		srv.RegisterTool(kubedagger.NewNetBypass(execr))
		srv.RegisterTool(kubedagger.NewMeshBypass(execr))
		srv.RegisterTool(kubedagger.NewObsPoison(execr))
		srv.RegisterTool(kubedagger.NewDNSExfil(execr))
		srv.RegisterTool(kubedagger.NewCovertChannel(execr))
		srv.RegisterTool(kubedagger.NewWebhook(execr))
		srv.RegisterTool(kubedagger.NewDaemonset(execr))
		srv.RegisterTool(kubedagger.NewKeyring(execr))
		srv.RegisterTool(kubedagger.NewTLSIntercept(execr))
		srv.RegisterTool(kubedagger.NewEtcdSteal(execr))
		srv.RegisterTool(kubedagger.NewLogTamper(execr))
		srv.RegisterTool(kubedagger.NewSyscallBypass(execr))
		srv.RegisterTool(kubedagger.NewAuditFilter(execr))
		srv.RegisterTool(kubedagger.NewPcapBlind(execr))
		srv.RegisterTool(kubedagger.NewPolymorph(execr))
		srv.RegisterTool(kubedagger.NewFilelessExec(execr))
		srv.RegisterTool(kubedagger.NewXDPShell(execr))
		srv.RegisterTool(kubedagger.NewARPSpoof(execr))
		srv.RegisterTool(kubedagger.NewKubelet(execr))
		srv.RegisterTool(kubedagger.NewVethHijack(execr))
		srv.RegisterTool(kubedagger.NewSidecarInject(execr))
		srv.RegisterTool(kubedagger.NewSupplyChain(execr))
		srv.RegisterTool(kubedagger.NewCRITamper(execr))
		srv.RegisterTool(kubedagger.NewSAToken(execr))
		srv.RegisterTool(kubedagger.NewPodIdentity(execr))
		srv.RegisterTool(kubedagger.NewGitOpsPoison(execr))
		srv.RegisterTool(kubedagger.NewCRDBackdoor(execr))
		srv.RegisterTool(kubedagger.NewHoneypotDetect(execr))
		srv.RegisterTool(kubedagger.NewK8sEventC2(execr))
		srv.RegisterTool(kubedagger.NewContainerLogC2(execr))
		srv.RegisterTool(kubedagger.NewDoHC2(execr))
		srv.RegisterTool(kubedagger.NewTCPStego(execr))
		srv.RegisterTool(kubedagger.NewBPFIPC(execr))
		srv.RegisterTool(kubedagger.NewSchedStarve(execr))
		srv.RegisterTool(kubedagger.NewFaultInject(execr))
		srv.RegisterTool(kubedagger.NewCgroupManip(execr))
		srv.RegisterTool(kubedagger.NewElectionDisrupt(execr))
		srv.RegisterTool(kubedagger.NewCertSabotage(execr))
		srv.RegisterTool(kubedagger.NewKeyringMITM(execr))
		srv.RegisterTool(kubedagger.NewCoredumpSuppress(execr))
		srv.RegisterTool(kubedagger.NewTimeskew(execr))
		srv.RegisterTool(kubedagger.NewSigBypass(execr))
		srv.RegisterTool(kubedagger.NewOperatorAgents(execr))
		srv.RegisterTool(kubedagger.NewOperatorShell(execr))
		srv.RegisterTool(kubedagger.NewOperatorModule(execr))
		srv.RegisterTool(kubedagger.NewOperatorTasks(execr))
	}

	// Barzakh UEFI toolset
	if cfg.ToolsetEnabled("barzakh") {
		srv.RegisterTool(barzakh.NewList(execr))
		srv.RegisterTool(barzakh.NewGenerate(execr))
		srv.RegisterTool(barzakh.NewCorpus(execr))
		srv.RegisterTool(barzakh.NewScan(execr))
	}

	// Health (always registered)
	srv.RegisterTool(health.NewHealthCheck(allBinaries))

	// Plugin tools
	pluginTools := plugin.LoadPlugins(cfg.PluginsDir, execr)
	for _, t := range pluginTools {
		srv.RegisterTool(t)
	}

	// Workflow engine
	wfEngine := workflow.NewEngine(func(ctx context.Context, toolName string, params json.RawMessage) (string, bool, error) {
		tool, ok := srv.GetTool(toolName)
		if !ok {
			return "", false, fmt.Errorf("unknown tool: %s", toolName)
		}
		result, err := tool.Execute(ctx, params)
		if err != nil {
			return "", false, err
		}
		text := ""
		for _, c := range result.Content {
			if c.Type == "text" {
				text += c.Text
			}
		}
		return text, !result.IsError, nil
	})
	srv.SetWorkflowRunner(wfEngine)

	// Report generator
	srv.SetReportGenerator(report.NewGenerator())

	// Start transport
	ctx := context.Background()
	switch cfg.Transport {
	case "sse":
		authCheck := auth.HTTPAuthCheck(authCfg)
		log.Printf("starting SSE transport on %s", cfg.SSEAddr)
		if err := srv.ServeSSEWithHandler(ctx, cfg.SSEAddr, authCheck); err != nil {
			log.Fatalf("SSE server error: %v", err)
		}
	case "ws":
		log.Printf("starting WebSocket transport on %s", cfg.WSAddr)
		if err := srv.ServeWebSocket(ctx, cfg.WSAddr); err != nil {
			log.Fatalf("WebSocket server error: %v", err)
		}
	default:
		if err := srv.ServeStdio(ctx); err != nil {
			log.Fatalf("server error: %v", err)
		}
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
