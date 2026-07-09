package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/yasindce1998/redhands/pkg/attackgraph"
	"github.com/yasindce1998/redhands/pkg/audit"
	"github.com/yasindce1998/redhands/pkg/auth"
	"github.com/yasindce1998/redhands/pkg/cache"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/credstore"
	"github.com/yasindce1998/redhands/pkg/dashboard"
	"github.com/yasindce1998/redhands/pkg/dryrun"
	"github.com/yasindce1998/redhands/pkg/engagement"
	"github.com/yasindce1998/redhands/pkg/evidence"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/loot"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/notify"
	"github.com/yasindce1998/redhands/pkg/opsec"
	"github.com/yasindce1998/redhands/pkg/plugin"
	"github.com/yasindce1998/redhands/pkg/ratelimit"
	"github.com/yasindce1998/redhands/pkg/report"
	"github.com/yasindce1998/redhands/pkg/targetdb"
	"github.com/yasindce1998/redhands/pkg/workflow"
	"github.com/yasindce1998/redhands/tools/ad/bloodhound"
	"github.com/yasindce1998/redhands/tools/ad/coercion"
	"github.com/yasindce1998/redhands/tools/ad/evilwinrm"
	"github.com/yasindce1998/redhands/tools/ad/responder"
	"github.com/yasindce1998/redhands/tools/analysis/tshark"
	"github.com/yasindce1998/redhands/tools/barzakh"
	"github.com/yasindce1998/redhands/tools/c2/sliver"
	"github.com/yasindce1998/redhands/tools/cloud"
	"github.com/yasindce1998/redhands/tools/crack/hashcat"
	"github.com/yasindce1998/redhands/tools/crack/john"
	"github.com/yasindce1998/redhands/tools/exploit/certipy"
	"github.com/yasindce1998/redhands/tools/exploit/crackmapexec"
	"github.com/yasindce1998/redhands/tools/exploit/impacket"
	"github.com/yasindce1998/redhands/tools/exploit/sqlmap"
	"github.com/yasindce1998/redhands/tools/fuzz/feroxbuster"
	"github.com/yasindce1998/redhands/tools/fuzz/ffuf"
	"github.com/yasindce1998/redhands/tools/fuzz/gobuster"
	"github.com/yasindce1998/redhands/tools/intelligence"
	"github.com/yasindce1998/redhands/tools/kubedagger"
	"github.com/yasindce1998/redhands/tools/mobile"
	"github.com/yasindce1998/redhands/tools/operations"
	"github.com/yasindce1998/redhands/tools/recon/amass"
	"github.com/yasindce1998/redhands/tools/recon/arjun"
	"github.com/yasindce1998/redhands/tools/recon/dns"
	"github.com/yasindce1998/redhands/tools/recon/gau"
	"github.com/yasindce1998/redhands/tools/recon/subfinder"
	"github.com/yasindce1998/redhands/tools/recon/wayback"
	"github.com/yasindce1998/redhands/tools/reporting"
	nmaptools "github.com/yasindce1998/redhands/tools/scan/nmap"
	"github.com/yasindce1998/redhands/tools/scan/masscan"
	"github.com/yasindce1998/redhands/tools/scan/rustscan"
	"github.com/yasindce1998/redhands/tools/social/phishing"
	"github.com/yasindce1998/redhands/tools/system/health"
	targetdbtools "github.com/yasindce1998/redhands/tools/targetdb"
	"github.com/yasindce1998/redhands/tools/tunnel/chisel"
	"github.com/yasindce1998/redhands/tools/tunnel/ligolo"
	"github.com/yasindce1998/redhands/tools/vuln/nuclei"
	"github.com/yasindce1998/redhands/tools/web/httpx"
	"github.com/yasindce1998/redhands/tools/web/katana"
	"github.com/yasindce1998/redhands/tools/web/nikto"
	"github.com/yasindce1998/redhands/tools/web/testssl"
	"github.com/yasindce1998/redhands/tools/web/whatweb"
	"github.com/yasindce1998/redhands/tools/wireless"
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
	"barzakh-adversary", "barzakh-scanner",
	// AD toolset
	"bloodhound-python", "responder", "evil-winrm", "python3",
	// Wireless
	"airmon-ng", "airodump-ng", "aircrack-ng", "bettercap",
	// Mobile
	"frida", "objection", "apktool", "adb",
	// Cloud
	"scout", "prowler", "pacu", "roadtx",
	// Evidence
	"cutycapt",
	// PDF
	"wkhtmltopdf",
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

	// Core stores
	tdb := targetdb.NewStore(cfg.TargetDBFile, cfg.TargetDBAutoSave)
	graph := attackgraph.New()
	engMgr := engagement.NewManager(cfg.EngagementDir)
	lootStore := loot.NewStore(cfg.LootDir)
	notifier := notify.NewNotifier(cfg.WebhookURLs, cfg.WebhookEvents)

	var credStore *credstore.Store
	if cfg.CredStoreKey != "" {
		credStore, err = credstore.NewStore(cfg.CredStoreFile, cfg.CredStoreKey)
		if err != nil {
			log.Printf("warning: credstore initialization failed: %v", err)
		}
	}

	var evidenceStore *evidence.Store
	evidenceStore, err = evidence.NewStore(cfg.EvidenceDir)
	if err != nil {
		log.Printf("warning: evidence store initialization failed: %v", err)
	}

	srv := mcp.NewServer("redhands", "0.1.0")

	// Dry-run middleware (must be first - intercepts all tool calls)
	if cfg.DryRun {
		dryrunInterceptor := dryrun.NewInterceptor()
		srv.Use(dryrunInterceptor.Middleware)
	}

	srv.Use(audit.Middleware(auditLogger))
	srv.Use(ratelimit.Middleware(limiter))
	srv.Use(cache.Middleware(resultCache))

	if authCfg.Mode != "none" {
		srv.Use(auth.Middleware(authCfg))
	}

	// OPSEC middleware
	if cfg.OpsecProfile != "" {
		tracker := opsec.NewTracker(cfg.IOCFile)
		opsecMw := opsec.NewMiddleware(cfg.OpsecProfile, tracker)
		srv.Use(opsecMw.Wrap)
	}

	// ─── Nmap toolset ───
	if cfg.ToolsetEnabled("nmap") {
		srv.RegisterTool(nmaptools.NewPortScan(execr))
		srv.RegisterTool(nmaptools.NewServiceDetect(execr))
		srv.RegisterTool(nmaptools.NewOSDetect(execr))
		srv.RegisterTool(nmaptools.NewVulnScan(execr))
	}

	// ─── Recon toolset ───
	if cfg.ToolsetEnabled("recon") {
		srv.RegisterTool(subfinder.NewSubdomainEnum(execr))
		srv.RegisterTool(amass.NewASNEnum(execr))
		srv.RegisterTool(dns.NewDNSLookup(execr))
		srv.RegisterTool(wayback.NewWayback(execr))
		srv.RegisterTool(gau.NewGAU(execr))
		srv.RegisterTool(arjun.NewArjun(execr))
	}

	// ─── Web toolset ───
	if cfg.ToolsetEnabled("web") {
		srv.RegisterTool(httpx.NewHTTPProbe(execr))
		srv.RegisterTool(katana.NewCrawl(execr))
		srv.RegisterTool(nikto.NewWebScan(execr))
		srv.RegisterTool(whatweb.NewFingerprint(execr))
		srv.RegisterTool(testssl.NewTLSScan(execr))
	}

	// ─── Fuzzing toolset ───
	if cfg.ToolsetEnabled("fuzz") {
		srv.RegisterTool(ffuf.NewWebFuzz(execr))
		srv.RegisterTool(gobuster.NewDirBust(execr))
		srv.RegisterTool(feroxbuster.NewFeroxbuster(execr))
	}

	// ─── Scanning toolset ───
	if cfg.ToolsetEnabled("scan") {
		srv.RegisterTool(masscan.NewMasscan(execr))
		srv.RegisterTool(rustscan.NewRustScan(execr))
	}

	// ─── Exploit toolset ───
	if cfg.ToolsetEnabled("exploit") {
		srv.RegisterTool(sqlmap.NewSQLMap(execr))
	}

	// ─── Vuln toolset ───
	if cfg.ToolsetEnabled("vuln") {
		srv.RegisterTool(nuclei.NewNucleiScan(execr))
	}

	// ─── Impacket toolset ───
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

	// ─── Sliver C2 toolset ───
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

	// ─── Chisel/Ligolo tunneling toolset ───
	if cfg.ToolsetEnabled("tunnel") {
		srv.RegisterTool(chisel.NewServer(execr))
		srv.RegisterTool(chisel.NewClient(execr))
		srv.RegisterTool(ligolo.NewProxyStart(execr))
		srv.RegisterTool(ligolo.NewRoute(execr))
		srv.RegisterTool(ligolo.NewListener(execr))
	}

	// ─── Hashcat/John cracking toolset ───
	if cfg.ToolsetEnabled("crack") {
		srv.RegisterTool(hashcat.NewCrack(execr))
		srv.RegisterTool(hashcat.NewBenchmark(execr))
		srv.RegisterTool(hashcat.NewShow(execr))
		srv.RegisterTool(john.NewCrack(execr))
		srv.RegisterTool(john.NewShow(execr))
		srv.RegisterTool(john.NewFormats(execr))
	}

	// ─── CrackMapExec toolset ───
	if cfg.ToolsetEnabled("crackmapexec") {
		srv.RegisterTool(crackmapexec.NewSMB(execr))
		srv.RegisterTool(crackmapexec.NewWinRM(execr))
		srv.RegisterTool(crackmapexec.NewLDAP(execr))
		srv.RegisterTool(crackmapexec.NewMSSQL(execr))
		srv.RegisterTool(crackmapexec.NewSSH(execr))
	}

	// ─── Certipy toolset ───
	if cfg.ToolsetEnabled("certipy") {
		srv.RegisterTool(certipy.NewFind(execr))
		srv.RegisterTool(certipy.NewRequest(execr))
		srv.RegisterTool(certipy.NewAuth(execr))
		srv.RegisterTool(certipy.NewShadow(execr))
		srv.RegisterTool(certipy.NewForge(execr))
		srv.RegisterTool(certipy.NewRelay(execr))
	}

	// ─── tshark toolset ───
	if cfg.ToolsetEnabled("tshark") {
		srv.RegisterTool(tshark.NewCapture(execr))
		srv.RegisterTool(tshark.NewRead(execr))
		srv.RegisterTool(tshark.NewStats(execr))
		srv.RegisterTool(tshark.NewExtract(execr))
		srv.RegisterTool(tshark.NewFollow(execr))
	}

	// ─── KubeDagger toolset ───
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

	// ─── Barzakh UEFI toolset ───
	if cfg.ToolsetEnabled("barzakh") {
		srv.RegisterTool(barzakh.NewList(execr))
		srv.RegisterTool(barzakh.NewGenerate(execr))
		srv.RegisterTool(barzakh.NewCorpus(execr))
		srv.RegisterTool(barzakh.NewScan(execr))
	}

	// ─── BloodHound AD toolset ───
	if cfg.ToolsetEnabled("bloodhound") {
		srv.RegisterTool(bloodhound.NewCollect(execr))
		srv.RegisterTool(bloodhound.NewFindPath(execr))
		srv.RegisterTool(bloodhound.NewMarkOwned(execr))
		srv.RegisterTool(bloodhound.NewAnalyze(execr))
	}

	// ─── Responder toolset ───
	if cfg.ToolsetEnabled("responder") {
		srv.RegisterTool(responder.NewStartTool(execr))
		srv.RegisterTool(responder.NewAnalyzeTool(execr))
		srv.RegisterTool(responder.NewLogsTool(execr))
		srv.RegisterTool(responder.NewStatusTool(execr))
	}

	// ─── Evil-WinRM toolset ───
	if cfg.ToolsetEnabled("evilwinrm") {
		srv.RegisterTool(evilwinrm.NewShell(execr))
		srv.RegisterTool(evilwinrm.NewUpload(execr))
		srv.RegisterTool(evilwinrm.NewDownload(execr))
		srv.RegisterTool(evilwinrm.NewDllInject(execr))
		srv.RegisterTool(evilwinrm.NewPsExec(execr))
	}

	// ─── Coercion toolset ───
	if cfg.ToolsetEnabled("coercion") {
		srv.RegisterTool(coercion.NewPetitPotam(execr))
		srv.RegisterTool(coercion.NewPrinterBug(execr))
		srv.RegisterTool(coercion.NewDFSCoerce(execr))
		srv.RegisterTool(coercion.NewCheck(execr))
	}

	// ─── Phishing toolset ───
	if cfg.ToolsetEnabled("phishing") {
		gophishURL := os.Getenv("REDHANDS_GOPHISH_URL")
		gophishKey := os.Getenv("REDHANDS_GOPHISH_API_KEY")
		if gophishURL != "" && gophishKey != "" {
			client := phishing.NewClient(gophishURL, gophishKey)
			srv.RegisterTool(phishing.NewCampaignCreate(client))
			srv.RegisterTool(phishing.NewCampaignStatus(client))
			srv.RegisterTool(phishing.NewTemplateCreate(client))
			srv.RegisterTool(phishing.NewLandingPageCreate(client))
			srv.RegisterTool(phishing.NewGroupsCreate(client))
		}
	}

	// ─── Wireless toolset ───
	if cfg.ToolsetEnabled("wireless") {
		srv.RegisterTool(wireless.NewMonitor(execr))
		srv.RegisterTool(wireless.NewScan(execr))
		srv.RegisterTool(wireless.NewDeauth(execr))
		srv.RegisterTool(wireless.NewCapture(execr))
		srv.RegisterTool(wireless.NewCrack(execr))
		srv.RegisterTool(wireless.NewBettercap(execr))
	}

	// ─── Mobile toolset ───
	if cfg.ToolsetEnabled("mobile") {
		srv.RegisterTool(mobile.NewFridaAttach(execr))
		srv.RegisterTool(mobile.NewFridaSpawn(execr))
		srv.RegisterTool(mobile.NewObjection(execr))
		srv.RegisterTool(mobile.NewApkDecompile(execr))
		srv.RegisterTool(mobile.NewApkRepackage(execr))
		srv.RegisterTool(mobile.NewAdbShell(execr))
	}

	// ─── Cloud toolset ───
	if cfg.ToolsetEnabled("cloud") {
		srv.RegisterTool(cloud.NewScoutAWS(execr))
		srv.RegisterTool(cloud.NewScoutAzure(execr))
		srv.RegisterTool(cloud.NewProwler(execr))
		srv.RegisterTool(cloud.NewPacuEnum(execr))
		srv.RegisterTool(cloud.NewRoadtoolsAuth(execr))
		srv.RegisterTool(cloud.NewRoadtoolsDump(execr))
		srv.RegisterTool(cloud.NewEnumS3(execr))
		srv.RegisterTool(cloud.NewEnumBlobs(execr))
	}

	// ─── Target Database tools ───
	if cfg.ToolsetEnabled("targetdb") {
		srv.RegisterTool(targetdbtools.NewAddHostTool(tdb))
		srv.RegisterTool(targetdbtools.NewListHostsTool(tdb))
		srv.RegisterTool(targetdbtools.NewAddFindingTool(tdb))
		srv.RegisterTool(targetdbtools.NewQueryFindingsTool(tdb))
		srv.RegisterTool(targetdbtools.NewAddCredTool(tdb))
		srv.RegisterTool(targetdbtools.NewListCredsTool(tdb))
	}

	// ─── Intelligence tools ───
	if cfg.ToolsetEnabled("intelligence") {
		srv.RegisterTool(intelligence.NewCorrelationTool(tdb))
		srv.RegisterTool(intelligence.NewAttackGraphBuildTool(tdb, graph))
		srv.RegisterTool(intelligence.NewAttackGraphPathTool(graph))
		srv.RegisterTool(intelligence.NewAttackGraphExportTool(graph))
		srv.RegisterTool(intelligence.NewMitreLookupTool())
		srv.RegisterTool(intelligence.NewRiskScoreTool())
	}

	// ─── Operations tools ───
	if cfg.ToolsetEnabled("operations") {
		srv.RegisterTool(operations.NewEngagementCreateTool(engMgr))
		srv.RegisterTool(operations.NewEngagementSwitchTool(engMgr))
		srv.RegisterTool(operations.NewEngagementListTool(engMgr))
		srv.RegisterTool(operations.NewLootAddTool(lootStore))
		srv.RegisterTool(operations.NewLootListTool(lootStore))
		srv.RegisterTool(operations.NewLootSearchTool(lootStore))
		if credStore != nil {
			srv.RegisterTool(operations.NewCredstoreAddTool(credStore))
			srv.RegisterTool(operations.NewCredstoreSearchTool(credStore))
		}
	}

	// ─── Reporting tools ───
	if cfg.ToolsetEnabled("reporting") {
		srv.RegisterTool(reporting.NewSARIFTool(tdb))
		srv.RegisterTool(reporting.NewExecutiveSummaryTool(tdb))
		srv.RegisterTool(reporting.NewComplianceTool(tdb))
		if evidenceStore != nil {
			srv.RegisterTool(reporting.NewEvidenceListTool(evidenceStore))
			srv.RegisterTool(reporting.NewEvidenceScreenshotTool(evidenceStore))
		}
	}

	// Health (always registered)
	srv.RegisterTool(health.NewHealthCheck(allBinaries))

	// Plugin tools
	pluginTools := plugin.LoadPlugins(cfg.PluginsDir, execr)
	for _, t := range pluginTools {
		srv.RegisterTool(t)
	}

	// Plugin hot-reload watcher
	if cfg.PluginsDir != "" {
		watcher := plugin.NewWatcher(cfg.PluginsDir, cfg.PluginPollInterval, func(path string) error {
			newTools := plugin.LoadPlugins(cfg.PluginsDir, execr)
			for _, t := range newTools {
				srv.RegisterTool(t)
			}
			log.Printf("hot-reloaded plugins (trigger: %s)", path)
			return nil
		})
		watcher.Start()
		defer watcher.Stop()
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

	// Suppress unused variable warnings for notifier
	_ = notifier

	// Start transport
	ctx := context.Background()

	// Dashboard HTTP server (if configured)
	if cfg.DashboardAddr != "" {
		dash := dashboard.New(tdb)
		go func() {
			log.Printf("starting dashboard on %s", cfg.DashboardAddr)
			if err := http.ListenAndServe(cfg.DashboardAddr, dash); err != nil {
				log.Printf("dashboard error: %v", err)
			}
		}()
	}

	// TCP transport (additional, runs alongside primary)
	if cfg.TCPAddr != "" {
		tcpTransport, err := mcp.NewTCPTransport(cfg.TCPAddr, srv.HandleRaw)
		if err != nil {
			log.Fatalf("failed to start TCP transport: %v", err)
		}
		defer tcpTransport.Close()
		go func() {
			log.Printf("starting TCP transport on %s", tcpTransport.Addr())
			if err := tcpTransport.Serve(); err != nil {
				log.Printf("TCP transport error: %v", err)
			}
		}()
	}

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
