package aegis

import (
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Tools returns the dependency-free tools in the aegis toolset: file
// analysis, reference data, config management and dry-run planning. None of
// them execute the Aegis-Shadow binaries. The daemon lifecycle tools
// (aegis_defense_start/stop/status and aegis_offense_start/stop/status)
// need a BackgroundManager and are constructed separately; the registry
// wires them centrally.
func Tools() []mcp.Tool {
	return []mcp.Tool{
		NewAlertsParse(),
		NewAlertsTail(),
		NewModulesList(),
		NewDefenseConfigRead(),
		NewDefenseConfigWrite(),
		NewOffensePlan(),
	}
}
