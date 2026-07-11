package registry

import (
	"os"

	"github.com/yasindce1998/redhands/internal/binaries"
	"github.com/yasindce1998/redhands/pkg/attackgraph"
	"github.com/yasindce1998/redhands/pkg/config"
	"github.com/yasindce1998/redhands/pkg/credstore"
	"github.com/yasindce1998/redhands/pkg/engagement"
	"github.com/yasindce1998/redhands/pkg/evidence"
	"github.com/yasindce1998/redhands/pkg/executor"
	"github.com/yasindce1998/redhands/pkg/loot"
	"github.com/yasindce1998/redhands/pkg/mcp"
	"github.com/yasindce1998/redhands/pkg/targetdb"
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

type Deps struct {
	Exec      executor.Executor
	Cfg       *config.Config
	TargetDB  *targetdb.Store
	Graph     *attackgraph.Graph
	EngMgr    *engagement.Manager
	Loot      *loot.Store
	CredStore *credstore.Store
	Evidence  *evidence.Store
}

func RegisterAll(srv *mcp.Server, d *Deps) {
	if d.Cfg.ToolsetEnabled("nmap") {
		srv.RegisterTool(nmaptools.NewPortScan(d.Exec))
		srv.RegisterTool(nmaptools.NewServiceDetect(d.Exec))
		srv.RegisterTool(nmaptools.NewOSDetect(d.Exec))
		srv.RegisterTool(nmaptools.NewVulnScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("recon") {
		srv.RegisterTool(subfinder.NewSubdomainEnum(d.Exec))
		srv.RegisterTool(amass.NewASNEnum(d.Exec))
		srv.RegisterTool(dns.NewDNSLookup(d.Exec))
		srv.RegisterTool(wayback.NewWayback(d.Exec))
		srv.RegisterTool(gau.NewGAU(d.Exec))
		srv.RegisterTool(arjun.NewArjun(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("web") {
		srv.RegisterTool(httpx.NewHTTPProbe(d.Exec))
		srv.RegisterTool(katana.NewCrawl(d.Exec))
		srv.RegisterTool(nikto.NewWebScan(d.Exec))
		srv.RegisterTool(whatweb.NewFingerprint(d.Exec))
		srv.RegisterTool(testssl.NewTLSScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("fuzz") {
		srv.RegisterTool(ffuf.NewWebFuzz(d.Exec))
		srv.RegisterTool(gobuster.NewDirBust(d.Exec))
		srv.RegisterTool(feroxbuster.NewFeroxbuster(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("scan") {
		srv.RegisterTool(masscan.NewMasscan(d.Exec))
		srv.RegisterTool(rustscan.NewRustScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("exploit") {
		srv.RegisterTool(sqlmap.NewSQLMap(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("vuln") {
		srv.RegisterTool(nuclei.NewNucleiScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("impacket") {
		srv.RegisterTool(impacket.NewSecretsDump(d.Exec))
		srv.RegisterTool(impacket.NewPsExec(d.Exec))
		srv.RegisterTool(impacket.NewWmiExec(d.Exec))
		srv.RegisterTool(impacket.NewSMBClient(d.Exec))
		srv.RegisterTool(impacket.NewDcomExec(d.Exec))
		srv.RegisterTool(impacket.NewGetTGT(d.Exec))
		srv.RegisterTool(impacket.NewGetST(d.Exec))
		srv.RegisterTool(impacket.NewNTLMRelay(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("sliver") {
		srv.RegisterTool(sliver.NewGenerate(d.Exec))
		srv.RegisterTool(sliver.NewListeners(d.Exec))
		srv.RegisterTool(sliver.NewSessions(d.Exec))
		srv.RegisterTool(sliver.NewBeacons(d.Exec))
		srv.RegisterTool(sliver.NewExecute(d.Exec))
		srv.RegisterTool(sliver.NewUpload(d.Exec))
		srv.RegisterTool(sliver.NewDownload(d.Exec))
		srv.RegisterTool(sliver.NewPivot(d.Exec))
		srv.RegisterTool(sliver.NewPortFwd(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("tunnel") {
		srv.RegisterTool(chisel.NewServer(d.Exec))
		srv.RegisterTool(chisel.NewClient(d.Exec))
		srv.RegisterTool(ligolo.NewProxyStart(d.Exec))
		srv.RegisterTool(ligolo.NewRoute(d.Exec))
		srv.RegisterTool(ligolo.NewListener(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("crack") {
		srv.RegisterTool(hashcat.NewCrack(d.Exec))
		srv.RegisterTool(hashcat.NewBenchmark(d.Exec))
		srv.RegisterTool(hashcat.NewShow(d.Exec))
		srv.RegisterTool(john.NewCrack(d.Exec))
		srv.RegisterTool(john.NewShow(d.Exec))
		srv.RegisterTool(john.NewFormats(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("crackmapexec") {
		srv.RegisterTool(crackmapexec.NewSMB(d.Exec))
		srv.RegisterTool(crackmapexec.NewWinRM(d.Exec))
		srv.RegisterTool(crackmapexec.NewLDAP(d.Exec))
		srv.RegisterTool(crackmapexec.NewMSSQL(d.Exec))
		srv.RegisterTool(crackmapexec.NewSSH(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("certipy") {
		srv.RegisterTool(certipy.NewFind(d.Exec))
		srv.RegisterTool(certipy.NewRequest(d.Exec))
		srv.RegisterTool(certipy.NewAuth(d.Exec))
		srv.RegisterTool(certipy.NewShadow(d.Exec))
		srv.RegisterTool(certipy.NewForge(d.Exec))
		srv.RegisterTool(certipy.NewRelay(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("tshark") {
		srv.RegisterTool(tshark.NewCapture(d.Exec))
		srv.RegisterTool(tshark.NewRead(d.Exec))
		srv.RegisterTool(tshark.NewStats(d.Exec))
		srv.RegisterTool(tshark.NewExtract(d.Exec))
		srv.RegisterTool(tshark.NewFollow(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("kubedagger") {
		srv.RegisterTool(kubedagger.NewNetworkScan(d.Exec))
		srv.RegisterTool(kubedagger.NewNetworkDiscovery(d.Exec))
		srv.RegisterTool(kubedagger.NewDockerList(d.Exec))
		srv.RegisterTool(kubedagger.NewDockerOverride(d.Exec))
		srv.RegisterTool(kubedagger.NewK8sDiscover(d.Exec))
		srv.RegisterTool(kubedagger.NewK8sAbuse(d.Exec))
		srv.RegisterTool(kubedagger.NewContainerEscape(d.Exec))
		srv.RegisterTool(kubedagger.NewSecretsHarvest(d.Exec))
		srv.RegisterTool(kubedagger.NewCloudMeta(d.Exec))
		srv.RegisterTool(kubedagger.NewCloudExfil(d.Exec))
		srv.RegisterTool(kubedagger.NewEvasion(d.Exec))
		srv.RegisterTool(kubedagger.NewNetBypass(d.Exec))
		srv.RegisterTool(kubedagger.NewMeshBypass(d.Exec))
		srv.RegisterTool(kubedagger.NewObsPoison(d.Exec))
		srv.RegisterTool(kubedagger.NewDNSExfil(d.Exec))
		srv.RegisterTool(kubedagger.NewCovertChannel(d.Exec))
		srv.RegisterTool(kubedagger.NewWebhook(d.Exec))
		srv.RegisterTool(kubedagger.NewDaemonset(d.Exec))
		srv.RegisterTool(kubedagger.NewKeyring(d.Exec))
		srv.RegisterTool(kubedagger.NewTLSIntercept(d.Exec))
		srv.RegisterTool(kubedagger.NewEtcdSteal(d.Exec))
		srv.RegisterTool(kubedagger.NewLogTamper(d.Exec))
		srv.RegisterTool(kubedagger.NewSyscallBypass(d.Exec))
		srv.RegisterTool(kubedagger.NewAuditFilter(d.Exec))
		srv.RegisterTool(kubedagger.NewPcapBlind(d.Exec))
		srv.RegisterTool(kubedagger.NewPolymorph(d.Exec))
		srv.RegisterTool(kubedagger.NewFilelessExec(d.Exec))
		srv.RegisterTool(kubedagger.NewXDPShell(d.Exec))
		srv.RegisterTool(kubedagger.NewARPSpoof(d.Exec))
		srv.RegisterTool(kubedagger.NewKubelet(d.Exec))
		srv.RegisterTool(kubedagger.NewVethHijack(d.Exec))
		srv.RegisterTool(kubedagger.NewSidecarInject(d.Exec))
		srv.RegisterTool(kubedagger.NewSupplyChain(d.Exec))
		srv.RegisterTool(kubedagger.NewCRITamper(d.Exec))
		srv.RegisterTool(kubedagger.NewSAToken(d.Exec))
		srv.RegisterTool(kubedagger.NewPodIdentity(d.Exec))
		srv.RegisterTool(kubedagger.NewGitOpsPoison(d.Exec))
		srv.RegisterTool(kubedagger.NewCRDBackdoor(d.Exec))
		srv.RegisterTool(kubedagger.NewHoneypotDetect(d.Exec))
		srv.RegisterTool(kubedagger.NewK8sEventC2(d.Exec))
		srv.RegisterTool(kubedagger.NewContainerLogC2(d.Exec))
		srv.RegisterTool(kubedagger.NewDoHC2(d.Exec))
		srv.RegisterTool(kubedagger.NewTCPStego(d.Exec))
		srv.RegisterTool(kubedagger.NewBPFIPC(d.Exec))
		srv.RegisterTool(kubedagger.NewSchedStarve(d.Exec))
		srv.RegisterTool(kubedagger.NewFaultInject(d.Exec))
		srv.RegisterTool(kubedagger.NewCgroupManip(d.Exec))
		srv.RegisterTool(kubedagger.NewElectionDisrupt(d.Exec))
		srv.RegisterTool(kubedagger.NewCertSabotage(d.Exec))
		srv.RegisterTool(kubedagger.NewKeyringMITM(d.Exec))
		srv.RegisterTool(kubedagger.NewCoredumpSuppress(d.Exec))
		srv.RegisterTool(kubedagger.NewTimeskew(d.Exec))
		srv.RegisterTool(kubedagger.NewSigBypass(d.Exec))
		srv.RegisterTool(kubedagger.NewOperatorAgents(d.Exec))
		srv.RegisterTool(kubedagger.NewOperatorShell(d.Exec))
		srv.RegisterTool(kubedagger.NewOperatorModule(d.Exec))
		srv.RegisterTool(kubedagger.NewOperatorTasks(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("barzakh") {
		srv.RegisterTool(barzakh.NewList(d.Exec))
		srv.RegisterTool(barzakh.NewGenerate(d.Exec))
		srv.RegisterTool(barzakh.NewCorpus(d.Exec))
		srv.RegisterTool(barzakh.NewScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("bloodhound") {
		srv.RegisterTool(bloodhound.NewCollect(d.Exec))
		srv.RegisterTool(bloodhound.NewFindPath(d.Exec))
		srv.RegisterTool(bloodhound.NewMarkOwned(d.Exec))
		srv.RegisterTool(bloodhound.NewAnalyze(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("responder") {
		srv.RegisterTool(responder.NewStartTool(d.Exec))
		srv.RegisterTool(responder.NewAnalyzeTool(d.Exec))
		srv.RegisterTool(responder.NewLogsTool(d.Exec))
		srv.RegisterTool(responder.NewStatusTool(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("evilwinrm") {
		srv.RegisterTool(evilwinrm.NewShell(d.Exec))
		srv.RegisterTool(evilwinrm.NewUpload(d.Exec))
		srv.RegisterTool(evilwinrm.NewDownload(d.Exec))
		srv.RegisterTool(evilwinrm.NewDllInject(d.Exec))
		srv.RegisterTool(evilwinrm.NewPsExec(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("coercion") {
		srv.RegisterTool(coercion.NewPetitPotam(d.Exec))
		srv.RegisterTool(coercion.NewPrinterBug(d.Exec))
		srv.RegisterTool(coercion.NewDFSCoerce(d.Exec))
		srv.RegisterTool(coercion.NewCheck(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("phishing") {
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

	if d.Cfg.ToolsetEnabled("wireless") {
		srv.RegisterTool(wireless.NewMonitor(d.Exec))
		srv.RegisterTool(wireless.NewScan(d.Exec))
		srv.RegisterTool(wireless.NewDeauth(d.Exec))
		srv.RegisterTool(wireless.NewCapture(d.Exec))
		srv.RegisterTool(wireless.NewCrack(d.Exec))
		srv.RegisterTool(wireless.NewBettercap(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("mobile") {
		srv.RegisterTool(mobile.NewFridaAttach(d.Exec))
		srv.RegisterTool(mobile.NewFridaSpawn(d.Exec))
		srv.RegisterTool(mobile.NewObjection(d.Exec))
		srv.RegisterTool(mobile.NewApkDecompile(d.Exec))
		srv.RegisterTool(mobile.NewApkRepackage(d.Exec))
		srv.RegisterTool(mobile.NewAdbShell(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("cloud") {
		srv.RegisterTool(cloud.NewScoutAWS(d.Exec))
		srv.RegisterTool(cloud.NewScoutAzure(d.Exec))
		srv.RegisterTool(cloud.NewProwler(d.Exec))
		srv.RegisterTool(cloud.NewPacuEnum(d.Exec))
		srv.RegisterTool(cloud.NewRoadtoolsAuth(d.Exec))
		srv.RegisterTool(cloud.NewRoadtoolsDump(d.Exec))
		srv.RegisterTool(cloud.NewEnumS3(d.Exec))
		srv.RegisterTool(cloud.NewEnumBlobs(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("targetdb") {
		srv.RegisterTool(targetdbtools.NewAddHostTool(d.TargetDB))
		srv.RegisterTool(targetdbtools.NewListHostsTool(d.TargetDB))
		srv.RegisterTool(targetdbtools.NewAddFindingTool(d.TargetDB))
		srv.RegisterTool(targetdbtools.NewQueryFindingsTool(d.TargetDB))
		srv.RegisterTool(targetdbtools.NewAddCredTool(d.TargetDB))
		srv.RegisterTool(targetdbtools.NewListCredsTool(d.TargetDB))
	}

	if d.Cfg.ToolsetEnabled("intelligence") {
		srv.RegisterTool(intelligence.NewCorrelationTool(d.TargetDB))
		srv.RegisterTool(intelligence.NewAttackGraphBuildTool(d.TargetDB, d.Graph))
		srv.RegisterTool(intelligence.NewAttackGraphPathTool(d.Graph))
		srv.RegisterTool(intelligence.NewAttackGraphExportTool(d.Graph))
		srv.RegisterTool(intelligence.NewMitreLookupTool())
		srv.RegisterTool(intelligence.NewRiskScoreTool())
	}

	if d.Cfg.ToolsetEnabled("operations") {
		srv.RegisterTool(operations.NewEngagementCreateTool(d.EngMgr))
		srv.RegisterTool(operations.NewEngagementSwitchTool(d.EngMgr))
		srv.RegisterTool(operations.NewEngagementListTool(d.EngMgr))
		srv.RegisterTool(operations.NewLootAddTool(d.Loot))
		srv.RegisterTool(operations.NewLootListTool(d.Loot))
		srv.RegisterTool(operations.NewLootSearchTool(d.Loot))
		if d.CredStore != nil {
			srv.RegisterTool(operations.NewCredstoreAddTool(d.CredStore))
			srv.RegisterTool(operations.NewCredstoreSearchTool(d.CredStore))
		}
	}

	if d.Cfg.ToolsetEnabled("reporting") {
		srv.RegisterTool(reporting.NewSARIFTool(d.TargetDB))
		srv.RegisterTool(reporting.NewExecutiveSummaryTool(d.TargetDB))
		srv.RegisterTool(reporting.NewComplianceTool(d.TargetDB))
		if d.Evidence != nil {
			srv.RegisterTool(reporting.NewEvidenceListTool(d.Evidence))
			srv.RegisterTool(reporting.NewEvidenceScreenshotTool(d.Evidence))
		}
	}

	srv.RegisterTool(health.NewHealthCheck(binaries.All))
}
