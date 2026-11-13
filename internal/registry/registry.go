package registry

import (
	"log"
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
	"github.com/yasindce1998/redhands/tools/aegis"
	"github.com/yasindce1998/redhands/tools/analysis/tshark"
	"github.com/yasindce1998/redhands/tools/barzakh"
	"github.com/yasindce1998/redhands/tools/c2/sliver"
	"github.com/yasindce1998/redhands/tools/campaign"
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
	"github.com/yasindce1998/redhands/tools/msf"
	"github.com/yasindce1998/redhands/tools/operations"
	"github.com/yasindce1998/redhands/tools/recon/amass"
	"github.com/yasindce1998/redhands/tools/recon/arjun"
	"github.com/yasindce1998/redhands/tools/recon/dns"
	"github.com/yasindce1998/redhands/tools/recon/gau"
	"github.com/yasindce1998/redhands/tools/recon/subfinder"
	"github.com/yasindce1998/redhands/tools/recon/wayback"
	"github.com/yasindce1998/redhands/tools/reporting"
	"github.com/yasindce1998/redhands/tools/scan/masscan"
	nmaptools "github.com/yasindce1998/redhands/tools/scan/nmap"
	"github.com/yasindce1998/redhands/tools/scan/rustscan"
	"github.com/yasindce1998/redhands/tools/social/phishing"
	"github.com/yasindce1998/redhands/tools/system/health"
	targetdbtools "github.com/yasindce1998/redhands/tools/targetdb"
	"github.com/yasindce1998/redhands/tools/telecom"
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
	Exec        executor.Executor
	Cfg         *config.Config
	TargetDB    *targetdb.Store
	Graph       *attackgraph.Graph
	EngMgr      *engagement.Manager
	Loot        *loot.Store
	CredStore   *credstore.Store
	Evidence    *evidence.Store
	ProcMgr     *executor.BackgroundManager
	CampaignEng campaign.Engine
}

func RegisterAll(srv *mcp.Server, d *Deps) {
	// register adds a tool, reporting schema-rejection diagnostics to
	// stderr instead of failing startup (mirrors plugin conflict
	// handling; a rejected tool is simply absent from the catalog).
	register := func(t mcp.Tool) {
		if err := srv.RegisterTool(t); err != nil {
			log.Printf("registry: rejecting tool %q: %v", t.Name(), err)
		}
	}
	if d.Cfg.ToolsetEnabled("nmap") {
		register(nmaptools.NewPortScan(d.Exec))
		register(nmaptools.NewServiceDetect(d.Exec))
		register(nmaptools.NewOSDetect(d.Exec))
		register(nmaptools.NewVulnScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("recon") {
		register(subfinder.NewSubdomainEnum(d.Exec))
		register(amass.NewASNEnum(d.Exec))
		register(dns.NewDNSLookup(d.Exec))
		register(wayback.NewWayback(d.Exec))
		register(gau.NewGAU(d.Exec))
		register(arjun.NewArjun(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("web") {
		register(httpx.NewHTTPProbe(d.Exec))
		register(katana.NewCrawl(d.Exec))
		register(nikto.NewWebScan(d.Exec))
		register(whatweb.NewFingerprint(d.Exec))
		register(testssl.NewTLSScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("fuzz") {
		register(ffuf.NewWebFuzz(d.Exec))
		register(gobuster.NewDirBust(d.Exec))
		register(feroxbuster.NewFeroxbuster(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("scan") {
		register(masscan.NewMasscan(d.Exec))
		register(rustscan.NewRustScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("exploit") {
		register(sqlmap.NewSQLMap(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("vuln") {
		register(nuclei.NewNucleiScan(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("impacket") {
		register(impacket.NewSecretsDump(d.Exec))
		register(impacket.NewPsExec(d.Exec))
		register(impacket.NewWmiExec(d.Exec))
		register(impacket.NewSMBClient(d.Exec))
		register(impacket.NewDcomExec(d.Exec))
		register(impacket.NewGetTGT(d.Exec))
		register(impacket.NewGetST(d.Exec))
		register(impacket.NewNTLMRelay(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("sliver") {
		register(sliver.NewGenerate(d.Exec))
		register(sliver.NewListeners(d.Exec))
		register(sliver.NewSessions(d.Exec))
		register(sliver.NewBeacons(d.Exec))
		register(sliver.NewExecute(d.Exec))
		register(sliver.NewUpload(d.Exec))
		register(sliver.NewDownload(d.Exec))
		register(sliver.NewPivot(d.Exec))
		register(sliver.NewPortFwd(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("tunnel") {
		register(chisel.NewServer(d.Exec))
		register(chisel.NewClient(d.Exec))
		register(ligolo.NewProxyStart(d.Exec))
		register(ligolo.NewRoute(d.Exec))
		register(ligolo.NewListener(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("crack") {
		register(hashcat.NewCrack(d.Exec))
		register(hashcat.NewBenchmark(d.Exec))
		register(hashcat.NewShow(d.Exec))
		register(john.NewCrack(d.Exec))
		register(john.NewShow(d.Exec))
		register(john.NewFormats(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("crackmapexec") {
		register(crackmapexec.NewSMB(d.Exec))
		register(crackmapexec.NewWinRM(d.Exec))
		register(crackmapexec.NewLDAP(d.Exec))
		register(crackmapexec.NewMSSQL(d.Exec))
		register(crackmapexec.NewSSH(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("certipy") {
		register(certipy.NewFind(d.Exec))
		register(certipy.NewRequest(d.Exec))
		register(certipy.NewAuth(d.Exec))
		register(certipy.NewShadow(d.Exec))
		register(certipy.NewForge(d.Exec))
		register(certipy.NewRelay(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("tshark") {
		register(tshark.NewCapture(d.Exec))
		register(tshark.NewRead(d.Exec))
		register(tshark.NewStats(d.Exec))
		register(tshark.NewExtract(d.Exec))
		register(tshark.NewFollow(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("kubedagger") {
		register(kubedagger.NewNetworkScan(d.Exec))
		register(kubedagger.NewNetworkDiscovery(d.Exec))
		register(kubedagger.NewDockerList(d.Exec))
		register(kubedagger.NewDockerOverride(d.Exec))
		register(kubedagger.NewK8sDiscover(d.Exec))
		register(kubedagger.NewK8sAbuse(d.Exec))
		register(kubedagger.NewContainerEscape(d.Exec))
		register(kubedagger.NewSecretsHarvest(d.Exec))
		register(kubedagger.NewCloudMeta(d.Exec))
		register(kubedagger.NewCloudExfil(d.Exec))
		register(kubedagger.NewEvasion(d.Exec))
		register(kubedagger.NewNetBypass(d.Exec))
		register(kubedagger.NewMeshBypass(d.Exec))
		register(kubedagger.NewObsPoison(d.Exec))
		register(kubedagger.NewDNSExfil(d.Exec))
		register(kubedagger.NewCovertChannel(d.Exec))
		register(kubedagger.NewWebhook(d.Exec))
		register(kubedagger.NewDaemonset(d.Exec))
		register(kubedagger.NewKeyring(d.Exec))
		register(kubedagger.NewTLSIntercept(d.Exec))
		register(kubedagger.NewEtcdSteal(d.Exec))
		register(kubedagger.NewLogTamper(d.Exec))
		register(kubedagger.NewSyscallBypass(d.Exec))
		register(kubedagger.NewAuditFilter(d.Exec))
		register(kubedagger.NewPcapBlind(d.Exec))
		register(kubedagger.NewPolymorph(d.Exec))
		register(kubedagger.NewFilelessExec(d.Exec))
		register(kubedagger.NewXDPShell(d.Exec))
		register(kubedagger.NewARPSpoof(d.Exec))
		register(kubedagger.NewKubelet(d.Exec))
		register(kubedagger.NewVethHijack(d.Exec))
		register(kubedagger.NewSidecarInject(d.Exec))
		register(kubedagger.NewSupplyChain(d.Exec))
		register(kubedagger.NewCRITamper(d.Exec))
		register(kubedagger.NewSAToken(d.Exec))
		register(kubedagger.NewPodIdentity(d.Exec))
		register(kubedagger.NewGitOpsPoison(d.Exec))
		register(kubedagger.NewCRDBackdoor(d.Exec))
		register(kubedagger.NewHoneypotDetect(d.Exec))
		register(kubedagger.NewK8sEventC2(d.Exec))
		register(kubedagger.NewContainerLogC2(d.Exec))
		register(kubedagger.NewDoHC2(d.Exec))
		register(kubedagger.NewTCPStego(d.Exec))
		register(kubedagger.NewBPFIPC(d.Exec))
		register(kubedagger.NewSchedStarve(d.Exec))
		register(kubedagger.NewFaultInject(d.Exec))
		register(kubedagger.NewCgroupManip(d.Exec))
		register(kubedagger.NewElectionDisrupt(d.Exec))
		register(kubedagger.NewCertSabotage(d.Exec))
		register(kubedagger.NewKeyringMITM(d.Exec))
		register(kubedagger.NewCoredumpSuppress(d.Exec))
		register(kubedagger.NewTimeskew(d.Exec))
		register(kubedagger.NewSigBypass(d.Exec))
		register(kubedagger.NewOperatorAgents(d.Exec))
		register(kubedagger.NewOperatorShell(d.Exec))
		register(kubedagger.NewOperatorModule(d.Exec))
		register(kubedagger.NewOperatorTasks(d.Exec))
		register(kubedagger.NewOperatorStatus(d.Exec))
		register(kubedagger.NewFSWatch(d.Exec))
		register(kubedagger.NewPipeProg(d.Exec))
		register(kubedagger.NewPostgres(d.Exec))
		register(kubedagger.NewProctree(d.Exec))
		register(kubedagger.NewMITREExport(d.Exec))
		register(kubedagger.NewDetection(d.Exec))
		register(kubedagger.NewReport(d.Exec))
		register(kubedagger.NewVAPBackdoor(d.Exec))
		if d.ProcMgr != nil {
			register(kubedagger.NewServerStart(d.ProcMgr))
			register(kubedagger.NewServerStop(d.ProcMgr))
			register(kubedagger.NewServerStatus(d.ProcMgr))
		}
	}

	if d.Cfg.ToolsetEnabled("barzakh") {
		register(barzakh.NewList(d.Exec))
		register(barzakh.NewGenerate(d.Exec))
		register(barzakh.NewCorpus(d.Exec))
		register(barzakh.NewScan(d.Exec))
		register(barzakh.NewValidate(d.Exec))
		register(barzakh.NewScenario(d.Exec))
		register(barzakh.NewRobustness(d.Exec))
		register(barzakh.NewDetectors(d.Exec))
		register(barzakh.NewBaseline(d.Exec))
		register(barzakh.NewIntel(d.Exec))
		register(barzakh.NewInject(d.Exec))
		register(barzakh.NewEspBuild(d.Exec))
		register(barzakh.NewQemu(d.Exec))
		register(barzakh.NewRange(d.Exec))
		register(barzakh.NewFuzz(d.Exec))
		register(barzakh.NewHistory(d.Exec))
		register(barzakh.NewKb(d.Exec))
		register(barzakh.NewMl(d.Exec))
		register(barzakh.NewManifestValidate(d.Exec))
		register(barzakh.NewInfo(d.Exec))
		register(barzakh.NewReport(d.Exec))
		if d.ProcMgr != nil {
			register(barzakh.NewServerStart(d.ProcMgr))
			register(barzakh.NewServerStop(d.ProcMgr))
			register(barzakh.NewServerStatus(d.ProcMgr))
		}
	}

	if d.Cfg.ToolsetEnabled("telecom") {
		register(telecom.NewDoctor(d.Exec))
		register(telecom.NewFirmwareAnalyze(d.Exec))
		register(telecom.NewFirmwareExtract(d.Exec))
		register(telecom.NewFirmwareDiff(d.Exec))
		register(telecom.NewFirmwareNvDump(d.Exec))
		register(telecom.NewFirmwarePatch(d.Exec))
		register(telecom.NewFirmwareMonitor(d.Exec))
		register(telecom.NewSDRScan(d.Exec))
		register(telecom.NewSDRCapture(d.Exec))
		register(telecom.NewSDRInject(d.Exec))
		register(telecom.NewSDRRelay(d.Exec))
		register(telecom.NewSDRSelftest(d.Exec))
		register(telecom.NewThreats())
		register(telecom.NewAlerts())
		register(telecom.NewStats())
		if d.ProcMgr != nil {
			register(telecom.NewDefenseStart(d.ProcMgr))
			register(telecom.NewDefenseStop(d.ProcMgr))
			register(telecom.NewDefenseStatus(d.ProcMgr))
			register(telecom.NewOffenseStart(d.ProcMgr))
			register(telecom.NewOffenseStop(d.ProcMgr))
			register(telecom.NewOffenseStatus(d.ProcMgr))
			register(telecom.NewCorrelatorStart(d.ProcMgr))
			register(telecom.NewCorrelatorStop(d.ProcMgr))
			register(telecom.NewCorrelatorStatus(d.ProcMgr))
		}
	}

	if d.Cfg.ToolsetEnabled("msf") {
		register(msf.NewPayloadGenerate(d.Exec))
		register(msf.NewPayloadList(d.Exec))
		register(msf.NewModuleInfo(d.Exec))
		register(msf.NewModuleRun(d.Exec))
		register(msf.NewResourceRun(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("aegis") {
		register(aegis.NewAlertsParse())
		register(aegis.NewAlertsTail())
		register(aegis.NewModulesList())
		register(aegis.NewDefenseConfigRead())
		register(aegis.NewDefenseConfigWrite())
		register(aegis.NewOffensePlan())
		if d.ProcMgr != nil {
			register(aegis.NewDefenseStart(d.ProcMgr))
			register(aegis.NewDefenseStop(d.ProcMgr))
			register(aegis.NewDefenseStatus(d.ProcMgr))
			register(aegis.NewOffenseStart(d.ProcMgr))
			register(aegis.NewOffenseStop(d.ProcMgr))
			register(aegis.NewOffenseStatus(d.ProcMgr))
			register(aegis.NewC2Send(d.Exec))
		}
	}

	if d.Cfg.ToolsetEnabled("bloodhound") {
		register(bloodhound.NewCollect(d.Exec))
		register(bloodhound.NewFindPath(d.Exec))
		register(bloodhound.NewMarkOwned(d.Exec))
		register(bloodhound.NewAnalyze(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("responder") {
		register(responder.NewStartTool(d.Exec))
		register(responder.NewAnalyzeTool(d.Exec))
		register(responder.NewLogsTool(d.Exec))
		register(responder.NewStatusTool(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("evilwinrm") {
		register(evilwinrm.NewShell(d.Exec))
		register(evilwinrm.NewUpload(d.Exec))
		register(evilwinrm.NewDownload(d.Exec))
		register(evilwinrm.NewDllInject(d.Exec))
		register(evilwinrm.NewPsExec(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("coercion") {
		register(coercion.NewPetitPotam(d.Exec))
		register(coercion.NewPrinterBug(d.Exec))
		register(coercion.NewDFSCoerce(d.Exec))
		register(coercion.NewCheck(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("phishing") {
		gophishURL := os.Getenv("REDHANDS_GOPHISH_URL")
		gophishKey := os.Getenv("REDHANDS_GOPHISH_API_KEY")
		if gophishURL != "" && gophishKey != "" {
			client := phishing.NewClient(gophishURL, gophishKey)
			register(phishing.NewCampaignCreate(client))
			register(phishing.NewCampaignStatus(client))
			register(phishing.NewTemplateCreate(client))
			register(phishing.NewLandingPageCreate(client))
			register(phishing.NewGroupsCreate(client))
		}
	}

	if d.Cfg.ToolsetEnabled("wireless") {
		register(wireless.NewMonitor(d.Exec))
		register(wireless.NewScan(d.Exec))
		register(wireless.NewDeauth(d.Exec))
		register(wireless.NewCapture(d.Exec))
		register(wireless.NewCrack(d.Exec))
		register(wireless.NewBettercap(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("mobile") {
		register(mobile.NewFridaAttach(d.Exec))
		register(mobile.NewFridaSpawn(d.Exec))
		register(mobile.NewObjection(d.Exec))
		register(mobile.NewApkDecompile(d.Exec))
		register(mobile.NewApkRepackage(d.Exec))
		register(mobile.NewAdbShell(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("cloud") {
		register(cloud.NewScoutAWS(d.Exec))
		register(cloud.NewScoutAzure(d.Exec))
		register(cloud.NewProwler(d.Exec))
		register(cloud.NewPacuEnum(d.Exec))
		register(cloud.NewRoadtoolsAuth(d.Exec))
		register(cloud.NewRoadtoolsDump(d.Exec))
		register(cloud.NewEnumS3(d.Exec))
		register(cloud.NewEnumBlobs(d.Exec))
	}

	if d.Cfg.ToolsetEnabled("targetdb") {
		register(targetdbtools.NewAddHostTool(d.TargetDB))
		register(targetdbtools.NewListHostsTool(d.TargetDB))
		register(targetdbtools.NewAddFindingTool(d.TargetDB))
		register(targetdbtools.NewQueryFindingsTool(d.TargetDB))
		register(targetdbtools.NewAddCredTool(d.TargetDB))
		register(targetdbtools.NewListCredsTool(d.TargetDB))
	}

	if d.Cfg.ToolsetEnabled("intelligence") {
		register(intelligence.NewCorrelationTool(d.TargetDB))
		register(intelligence.NewAttackGraphBuildTool(d.TargetDB, d.Graph))
		register(intelligence.NewAttackGraphPathTool(d.Graph))
		register(intelligence.NewAttackGraphExportTool(d.Graph))
		register(intelligence.NewMitreLookupTool())
		register(intelligence.NewRiskScoreTool())
	}

	if d.Cfg.ToolsetEnabled("operations") {
		register(operations.NewEngagementCreateTool(d.EngMgr))
		register(operations.NewEngagementSwitchTool(d.EngMgr))
		register(operations.NewEngagementListTool(d.EngMgr))
		register(operations.NewLootAddTool(d.Loot))
		register(operations.NewLootListTool(d.Loot))
		register(operations.NewLootSearchTool(d.Loot))
		if d.CredStore != nil {
			register(operations.NewCredstoreAddTool(d.CredStore))
			register(operations.NewCredstoreSearchTool(d.CredStore))
		}
	}

	if d.Cfg.ToolsetEnabled("reporting") {
		register(reporting.NewSARIFTool(d.TargetDB))
		register(reporting.NewExecutiveSummaryTool(d.TargetDB))
		register(reporting.NewComplianceTool(d.TargetDB))
		if d.Evidence != nil {
			register(reporting.NewEvidenceListTool(d.Evidence))
			register(reporting.NewEvidenceScreenshotTool(d.Evidence, d.Exec))
		}
	}

	if d.Cfg.ToolsetEnabled("campaign") && d.CampaignEng != nil {
		register(campaign.NewStart(d.CampaignEng))
		register(campaign.NewStatus(d.CampaignEng))
		register(campaign.NewList(d.CampaignEng))
		register(campaign.NewResume(d.CampaignEng))
		register(campaign.NewCancel(d.CampaignEng))
		register(campaign.NewTemplates(d.CampaignEng))
		register(campaign.NewTemplateGet(d.CampaignEng))
		register(campaign.NewTemplateSave(d.CampaignEng))
	}

	register(health.NewHealthCheck(binaries.All))
	for name, policy := range builtinPolicies() {
		srv.SetToolPolicy(name, policy)
	}
}
