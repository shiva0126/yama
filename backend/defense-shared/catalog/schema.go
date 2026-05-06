package catalog

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Catalog provides a machine-readable detector and attack-pattern inventory.
// The full human-oriented coverage explanation lives in docs/ATTACK_PATTERN_CATALOG.md,
// while this structure is intended to drive future backend services.
type Catalog struct {
	Version   string      `yaml:"version"`
	Families  []Family    `yaml:"families"`
	Detectors []Detector  `yaml:"detectors"`
}

type Family struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Priority    int    `yaml:"priority"`
}

type Detector struct {
	ID                 string   `yaml:"id"`
	Name               string   `yaml:"name"`
	FamilyID           string   `yaml:"family_id"`
	Type               string   `yaml:"type"`
	MitreIDs           []string `yaml:"mitre_ids"`
	Aliases            []string `yaml:"aliases"`
	Description        string   `yaml:"description"`
	CorePreconditions  []string `yaml:"core_preconditions"`
	RequiredSignals    []string `yaml:"required_signals"`
	OptionalSignals    []string `yaml:"optional_signals"`
	ResponseCandidates []string `yaml:"response_candidates"`
	DetectorPriority   string   `yaml:"detector_priority"`
	ResponsePriority   string   `yaml:"response_priority"`
	SignalSpecs        []SignalSpec     `yaml:"signal_specs,omitempty"`
	Correlation        *CorrelationSpec `yaml:"correlation,omitempty"`
	Evidence           *EvidenceSpec    `yaml:"evidence,omitempty"`
	ResponsePolicy     *ResponsePolicy  `yaml:"response_policy,omitempty"`
	SourceRefs         []SourceRef      `yaml:"source_refs,omitempty"`
	DemoReady          bool             `yaml:"demo_ready,omitempty"`
}

// SignalSpec lets detector authors describe how a normalized signal should be
// interpreted without tying the detector to one raw event source.
type SignalSpec struct {
	Kind        string   `yaml:"kind"`
	EventIDs    []string `yaml:"event_ids,omitempty"`
	Attributes  []string `yaml:"attributes,omitempty"`
	Protocols   []string `yaml:"protocols,omitempty"`
	Notes       string   `yaml:"notes,omitempty"`
	Required    bool     `yaml:"required,omitempty"`
}

// CorrelationSpec captures the minimum pattern-completion logic required before
// the engine should emit a high-confidence detection or escalate to an incident.
type CorrelationSpec struct {
	Window           string   `yaml:"window,omitempty"`
	AnchorFields     []string `yaml:"anchor_fields,omitempty"`
	SecondarySignals []string `yaml:"secondary_signals,omitempty"`
	Escalation       string   `yaml:"escalation,omitempty"`
}

// EvidenceSpec enumerates the artifacts the defense plane should preserve
// whenever a detector fires and before any disruptive response is taken.
type EvidenceSpec struct {
	RequiredArtifacts []string `yaml:"required_artifacts,omitempty"`
	StorageClass      string   `yaml:"storage_class,omitempty"`
}

// ResponsePolicy defines the safe response posture for a detector.
type ResponsePolicy struct {
	Mode               string   `yaml:"mode,omitempty"`
	MinimumConfidence  string   `yaml:"minimum_confidence,omitempty"`
	ProtectedScopes    []string `yaml:"protected_scopes,omitempty"`
	RollbackArtifacts  []string `yaml:"rollback_artifacts,omitempty"`
}

// SourceRef points to the primary documentation or protocol references used to
// justify the detector's signal design.
type SourceRef struct {
	Title string `yaml:"title"`
	URL   string `yaml:"url"`
	Type  string `yaml:"type,omitempty"`
}

func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var catalog Catalog
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return nil, err
	}

	return &catalog, nil
}

func (c *Catalog) FamilyNameByID(id string) string {
	for _, family := range c.Families {
		if family.ID == id {
			return family.Name
		}
	}

	return id
}
