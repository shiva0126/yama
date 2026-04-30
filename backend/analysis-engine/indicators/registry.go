package indicators

import "ad-assessment/shared/types"

// Indicator is the interface every security check must implement.
// Add a new check by implementing this interface and calling Register()
// from an init() function in any file in this package.
type Indicator interface {
	// Metadata returns the static descriptor used for the indicator catalogue.
	Metadata() types.SecurityIndicator
	// Check evaluates the snapshot and returns zero or more findings.
	Check(snapshot *types.InventorySnapshot, scanID string) []types.Finding
}

var registry []Indicator

// Register adds an indicator to the global registry.
func Register(ind Indicator) {
	registry = append(registry, ind)
}

// RunAll executes every registered indicator and returns all findings.
func RunAll(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var all []types.Finding
	for _, ind := range registry {
		all = append(all, ind.Check(snapshot, scanID)...)
	}
	return all
}

// RegisteredCount returns how many indicators are loaded.
func RegisteredCount() int { return len(registry) }
