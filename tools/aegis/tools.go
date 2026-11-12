package aegis

import (
	"github.com/yasindce1998/redhands/pkg/mcp"
)

// Tools returns every tool in the aegis toolset. None of them execute the
// Aegis-Shadow binaries; the set is intentionally limited to file analysis,
// reference data, config management and dry-run planning.
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
