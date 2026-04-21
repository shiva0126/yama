package indicators

import (
	"fmt"
	"strings"

	"ad-assessment/shared/types"
)

// CheckADStructure runs AD structural security indicators
func CheckADStructure(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding

	findings = append(findings, checkTombstoneLifetime(snapshot, scanID)...)
	findings = append(findings, checkProtectedUsersEmpty(snapshot, scanID)...)
	findings = append(findings, checkDomainFunctionalLevel(snapshot, scanID)...)
	findings = append(findings, checkLAPSDeployment(snapshot, scanID)...)

	return findings
}

// CheckDelegation runs delegation-specific indicators
func CheckDelegation(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding
	findings = append(findings, checkUnconstrainedDelegation(snapshot, scanID)...)
	return findings
}

// CheckTrusts runs trust-specific indicators
func CheckTrusts(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding
	findings = append(findings, checkTrustSIDFiltering(snapshot, scanID)...)
	return findings
}

func checkTombstoneLifetime(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	for _, domain := range snapshot.Domains {
		if domain.TombstoneLifetime > 0 && domain.TombstoneLifetime < 180 {
			ind := findIndicator("S001")
			return []types.Finding{{
				ScanID:      scanID,
				IndicatorID: "S001",
				Name:        ind.Name,
				Description: fmt.Sprintf("Domain '%s' tombstone lifetime is %d days (recommended: 180+). Short tombstone lifetime impacts replication health and forensic capability.", domain.Name, domain.TombstoneLifetime),
				Severity:    types.SeverityLow,
				Category:    types.CategoryADStructure,
				RiskScore:   10,
				AffectedObjects: []types.AffectedObject{
					{Type: "Domain", Name: domain.Name, Detail: fmt.Sprintf("Tombstone lifetime: %d days", domain.TombstoneLifetime)},
				},
				Remediation: ind.Remediation,
				References:  ind.References,
				MITRE:       ind.MITRE,
			}}
		}
	}
	return nil
}

func checkProtectedUsersEmpty(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	for _, group := range snapshot.Groups {
		if strings.Contains(group.Name, "Protected Users") {
			if len(group.Members) == 0 {
				ind := findIndicator("S002")
				return []types.Finding{{
					ScanID:      scanID,
					IndicatorID: "S002",
					Name:        ind.Name,
					Description: "The Protected Users security group is empty. Privileged accounts are not receiving additional Kerberos and NTLM protections.",
					Severity:    types.SeverityMedium,
					Category:    types.CategoryADStructure,
					RiskScore:   20,
					AffectedObjects: []types.AffectedObject{
						{Type: "Group", Name: group.Name, DN: group.DistinguishedName, Detail: "Group is empty"},
					},
					Remediation: ind.Remediation,
					References:  ind.References,
					MITRE:       ind.MITRE,
				}}
			}
			return nil
		}
	}
	return nil
}

func checkDomainFunctionalLevel(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, domain := range snapshot.Domains {
		if domain.FunctionalLevel < 7 { // 7 = Server 2016
			levelName := domainFunctionalLevelName(domain.FunctionalLevel)
			affected = append(affected, types.AffectedObject{
				Type:   "Domain",
				Name:   domain.Name,
				Detail: fmt.Sprintf("Functional Level: %s (level %d)", levelName, domain.FunctionalLevel),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("DC005")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "DC005",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d domain(s) operating below Windows Server 2016 functional level, missing modern security features.", len(affected)),
		Severity:        types.SeverityMedium,
		Category:        types.CategoryADStructure,
		RiskScore:       20,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkLAPSDeployment(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	// Check computers (non-DC) for LAPS deployment
	var noLAPS []types.AffectedObject
	total := 0
	for _, comp := range snapshot.Computers {
		if comp.IsDomainController || !comp.Enabled {
			continue
		}
		total++
		if !comp.LAPSEnabled {
			noLAPS = append(noLAPS, types.AffectedObject{
				DN:     comp.DistinguishedName,
				Type:   "Computer",
				Name:   comp.Name,
				Detail: comp.OperatingSystem,
			})
		}
	}

	if total == 0 || len(noLAPS) == 0 {
		return nil
	}

	percentage := len(noLAPS) * 100 / total
	if percentage < 10 { // Less than 10% without LAPS is acceptable
		return nil
	}

	ind := findIndicator("S004")
	severity := types.SeverityMedium
	if percentage > 50 {
		severity = types.SeverityHigh
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "S004",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d of %d (%d%%) non-DC computers do not have LAPS deployed. Shared local admin passwords enable lateral movement.", len(noLAPS), total, percentage),
		Severity:        severity,
		Category:        types.CategoryADStructure,
		RiskScore:       20 + percentage/5,
		AffectedObjects: noLAPS,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkUnconstrainedDelegation(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, comp := range snapshot.Computers {
		if comp.TrustedForDelegation && !comp.IsDomainController && comp.Enabled {
			affected = append(affected, types.AffectedObject{
				DN:     comp.DistinguishedName,
				Type:   "Computer",
				Name:   comp.Name,
				Detail: fmt.Sprintf("OS: %s | Site: %s", comp.OperatingSystem, comp.Site),
			})
		}
	}
	for _, user := range snapshot.Users {
		if user.TrustedForDelegation && user.Enabled {
			affected = append(affected, types.AffectedObject{
				DN:     user.DistinguishedName,
				Type:   "User",
				Name:   user.SamAccountName,
				Detail: "User account with unconstrained delegation",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("K002")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "K002",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d non-DC account(s) are trusted for unconstrained Kerberos delegation. Compromising these enables TGT harvesting of connecting users.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryDelegation,
		RiskScore:       min(100, 40+len(affected)*10),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkTrustSIDFiltering(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, trust := range snapshot.Trusts {
		if !trust.SIDFiltering {
			affected = append(affected, types.AffectedObject{
				Type:   "Trust",
				Name:   trust.TargetDomain,
				Detail: fmt.Sprintf("Type: %s | Direction: %s | Transitive: %v", trust.TrustType, trust.TrustDirection, trust.IsTransitive),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("S003")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "S003",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d trust(s) without SID filtering. An attacker in a trusted domain can use SID history to escalate privileges in this domain.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryTrusts,
		RiskScore:       45 + len(affected)*5,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func domainFunctionalLevelName(level int) string {
	levels := map[int]string{
		0: "Windows 2000",
		1: "Windows Server 2003 Interim",
		2: "Windows Server 2003",
		3: "Windows Server 2008",
		4: "Windows Server 2008 R2",
		5: "Windows Server 2012",
		6: "Windows Server 2012 R2",
		7: "Windows Server 2016",
		8: "Windows Server 2019",
		9: "Windows Server 2022",
	}
	if name, ok := levels[level]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", level)
}
