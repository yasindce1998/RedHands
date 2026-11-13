# Registration wiring for the `campaign` toolset

This file is the hand-off note for the orchestrator: the exact lines needed
to register `tools/campaign` with the server. The package itself is
self-contained — it defines a local `Engine` interface that
`*workflow.EnhancedEngine` already satisfies (compile-time checked in
`campaign_test.go`), so nothing in `pkg/mcp` or `pkg/workflow` changes.

Recommended shape: **constructors take the `campaign.Engine` interface, and
`registry.Deps` gains one field for it.** `app.SetupCampaign` already
creates and returns the `*workflow.EnhancedEngine`; `main.go` just needs to
capture it and pass it in. (A factory closure would also work but adds an
indirection with no benefit since the engine is a singleton.)

## 1. `internal/registry/registry.go`

Add to the import block:

```go
"github.com/yasindce1998/redhands/tools/campaign"
```

Add a field to `Deps` (after `ProcMgr`, line ~73):

```go
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
	CampaignEng campaign.Engine // nil disables the campaign toolset
}
```

Add the toolset block inside `RegisterAll` (after the `reporting` block,
before the `health.NewHealthCheck` line, ~line 453):

```go
	if d.Cfg.ToolsetEnabled("campaign") && d.CampaignEng != nil {
		srv.RegisterTool(campaign.NewStart(d.CampaignEng))
		srv.RegisterTool(campaign.NewStatus(d.CampaignEng))
		srv.RegisterTool(campaign.NewList(d.CampaignEng))
		srv.RegisterTool(campaign.NewResume(d.CampaignEng))
		srv.RegisterTool(campaign.NewCancel(d.CampaignEng))
		srv.RegisterTool(campaign.NewTemplates(d.CampaignEng))
		srv.RegisterTool(campaign.NewTemplateGet(d.CampaignEng))
		srv.RegisterTool(campaign.NewTemplateSave(d.CampaignEng))
	}
```

The nil-guard keeps `RegisterAll` usable from tests/embedded builds that
never set up the campaign engine.

## 2. `cmd/redhands/main.go`

`app.SetupCampaign` already returns `*workflow.EnhancedEngine`, but it is
currently called AFTER `registry.RegisterAll` and its return value is
discarded (line ~80). The final order should look like:

```go
	app.SetupWorkflow(srv)
	campaignEngine := app.SetupCampaign(srv, &cfg, stores.TargetDB, stores.EngMgr)

	registry.RegisterAll(srv, &registry.Deps{
		Exec:        execr,
		Cfg:         &cfg,
		TargetDB:    stores.TargetDB,
		Graph:       stores.Graph,
		EngMgr:      stores.EngMgr,
		Loot:        stores.Loot,
		CredStore:   stores.CredStore,
		Evidence:    stores.Evidence,
		ProcMgr:     procMgr,
		CampaignEng: campaignEngine,
	})

	stopPlugins := app.SetupPlugins(srv, &cfg, execr)
	defer stopPlugins()
```

i.e. the diff is:

1. Move `app.SetupCampaign(...)` (and `app.SetupWorkflow(srv)` can stay
   where it is) ABOVE the `registry.RegisterAll(...)` call, and capture the
   result: `campaignEngine := app.SetupCampaign(...)`.
2. Add `CampaignEng: campaignEngine,` to the `registry.Deps` literal.

Moving `SetupCampaign` earlier is safe: it only constructs the engine,
wires `srv.SetCampaignEngine`, and sets the recorder/engagement check. Its
tool executor resolves tools through `srv.ExecuteTool` at call time, not at
construction time, so registration order does not matter to it.

## 3. (Recommended) `internal/registry/policy.go`

Tool annotations are derived from policies (`handler.go` builds
`ToolAnnotations{ReadOnlyHint: policy.ReadOnly, DestructiveHint:
!policy.ReadOnly, ...}`). Without an entry every campaign tool stays
approval-gated with all-false hints. Add to `builtinPolicies()`:

```go
	// Campaign engine: status/listing queries are read-only.
	for _, name := range []string{"campaign_status", "campaign_list", "campaign_templates", "campaign_template_get"} {
		policies[name] = mcp.ToolPolicy{ReadOnly: true, RetrySafe: true}
	}
	// Launching/resuming a campaign executes real tools against targets.
	for _, name := range []string{"campaign_start", "campaign_resume"} {
		policies[name] = mcp.ToolPolicy{NetworkAccess: true}
	}
	// Cancelling a run mutates operator state but is replayable.
	policies["campaign_cancel"] = mcp.ToolPolicy{RetrySafe: true}
	// Saving a playbook is a local file write; never executes anything.
	policies["campaign_template_save"] = mcp.ToolPolicy{}
```

This makes `campaign_start`/`campaign_resume` carry
`"destructiveHint": true` (the destructive annotation) and the query tools
`"readOnlyHint": true`.

## Config

No config change is required: `Config.ToolsetEnabled` defaults to
enabling every toolset when `Toolsets` is empty. Operators can restrict to
a set including `"campaign"` via the existing toolsets setting.
