package catalog

import (
	"time"

	"ad-assessment/defense-shared/events"
)

// CoverageSummary gives the demo API a compact view of detector readiness.
type CoverageSummary struct {
	Version          string         `json:"version"`
	FamilyCount      int            `json:"family_count"`
	DetectorCount    int            `json:"detector_count"`
	CriticalCount    int            `json:"critical_count"`
	HighCount        int            `json:"high_count"`
	DemoReadyCount   int            `json:"demo_ready_count"`
	ByFamily         map[string]int `json:"by_family"`
	ResponseProfiles map[string]int `json:"response_profiles"`
}

func BuildCoverageSummary(c *Catalog) CoverageSummary {
	summary := CoverageSummary{
		Version:          c.Version,
		FamilyCount:      len(c.Families),
		DetectorCount:    len(c.Detectors),
		ByFamily:         make(map[string]int),
		ResponseProfiles: make(map[string]int),
	}

	for _, detector := range c.Detectors {
		switch detector.DetectorPriority {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		}

		if detector.DemoReady {
			summary.DemoReadyCount++
		}

		summary.ByFamily[c.FamilyNameByID(detector.FamilyID)]++
		summary.ResponseProfiles[detector.ResponsePriority]++
	}

	return summary
}

// DemoDetections returns a small, deterministic set of detections so the demo
// API can show the attack path from signal to incident before the streaming
// pipeline is fully wired up.
func DemoDetections(now time.Time) []events.Detection {
	return []events.Detection{
		{
			ID:           "det-demo-dcsync-001",
			DetectorID:   "CRED-001",
			Title:        "Suspicious DCSync against crown-jewel domain controller",
			Confidence:   "critical-confirmed",
			Severity:     "critical",
			OccurredAt:   now.Add(-12 * time.Minute),
			Domain:       "shivasecurity.local",
			SourceHost:   "WKSTN-07",
			Actor:        "svc.backup-legacy",
			Target:       "DC01$",
			EvidenceRefs: []string{"ev-4662-01", "rpc-drsuapi-01", "acl-domain-01"},
			Metadata: map[string]string{
				"chain":       "replication-rights + drsuapi + source-mismatch",
				"attack_path": "ACL grant -> replication request -> KRBTGT target access",
			},
		},
		{
			ID:           "det-demo-esc8-001",
			DetectorID:   "ADCS-008",
			Title:        "NTLM relay to AD CS web enrollment",
			Confidence:   "high",
			Severity:     "critical",
			OccurredAt:   now.Add(-8 * time.Minute),
			Domain:       "shivasecurity.local",
			SourceHost:   "APP-12",
			Actor:        "DC01$",
			Target:       "ca01.shivasecurity.local",
			EvidenceRefs: []string{"relay-http-01", "coerce-efsr-01", "cert-issue-01"},
			Metadata: map[string]string{
				"chain":       "coercion + NTLM relay + HTTP enrollment",
				"attack_path": "PetitPotam -> relay -> machine certificate issuance",
			},
		},
		{
			ID:           "det-demo-shadowcreds-001",
			DetectorID:   "ACL-004",
			Title:        "Shadow credentials written to Tier 0 admin account",
			Confidence:   "high",
			Severity:     "critical",
			OccurredAt:   now.Add(-4 * time.Minute),
			Domain:       "shivasecurity.local",
			SourceHost:   "ADM-JUMP-01",
			Actor:        "helpdesk.sync",
			Target:       "Administrator",
			EvidenceRefs: []string{"ev-5136-01", "attr-kcl-01", "pkinit-4768-01"},
			Metadata: map[string]string{
				"chain":       "key credential write + PKINIT auth",
				"attack_path": "WriteKeyCredentialLink -> forged key trust logon",
			},
		},
	}
}

func DemoIncidents(now time.Time) []events.Incident {
	return []events.Incident{
		{
			ID:            "inc-demo-001",
			Title:         "Credential replication and certificate takeover campaign",
			Severity:      "critical",
			Confidence:    "critical-confirmed",
			Status:        "open",
			PrimaryActor:  "svc.backup-legacy",
			PrimaryTarget: "Tier0",
			OpenedAt:      now.Add(-12 * time.Minute),
			LastUpdatedAt: now.Add(-2 * time.Minute),
			DetectionIDs: []string{
				"det-demo-dcsync-001",
				"det-demo-esc8-001",
				"det-demo-shadowcreds-001",
			},
			ResponseActions: []string{
				"disable-account:svc.backup-legacy",
				"disable-template:Machine",
				"revert-attribute:msDS-KeyCredentialLink",
			},
			Metadata: map[string]string{
				"blast_radius": "Domain compromise path to KRBTGT, CA, and Tier 0 admin",
				"story":        "Assessment exposed the path, defense confirmed active exploitation.",
			},
		},
	}
}
