package indicators

import (
	"fmt"

	"ad-assessment/shared/types"
)

// CheckGroupPolicy runs all Group Policy indicators
func CheckGroupPolicy(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding

	findings = append(findings, checkLockoutPolicy(snapshot, scanID)...)
	findings = append(findings, checkWeakPasswordPolicy(snapshot, scanID)...)
	findings = append(findings, checkSYSVOLPermissions(snapshot, scanID)...)
	findings = append(findings, checkOrphanedGPOs(snapshot, scanID)...)
	findings = append(findings, checkWDigestViaGPO(snapshot, scanID)...)

	return findings
}

func checkLockoutPolicy(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	// Check domain-level lockout policy
	for _, domain := range snapshot.Domains {
		if domain.LockoutThreshold == 0 {
			ind := findIndicator("G001")
			return []types.Finding{{
				ScanID:      scanID,
				IndicatorID: "G001",
				Name:        ind.Name,
				Description: fmt.Sprintf("Domain '%s' has no account lockout threshold configured (threshold=0). Unlimited password guessing is possible.", domain.Name),
				Severity:    types.SeverityHigh,
				Category:    types.CategoryGroupPolicy,
				RiskScore:   55,
				AffectedObjects: []types.AffectedObject{
					{Type: "Domain", Name: domain.Name, Detail: "Lockout threshold: 0 (disabled)"},
				},
				Remediation: ind.Remediation,
				References:  ind.References,
				MITRE:       ind.MITRE,
			}}
		}
	}
	return nil
}

func checkWeakPasswordPolicy(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	var issues []string

	for _, domain := range snapshot.Domains {
		if domain.MinPwdLength < 14 {
			issues = append(issues, fmt.Sprintf("Min length: %d (recommended: 14+)", domain.MinPwdLength))
			affected = append(affected, types.AffectedObject{
				Type:   "Domain",
				Name:   domain.Name,
				Detail: fmt.Sprintf("Min password length: %d", domain.MinPwdLength),
			})
		}
		if domain.PwdHistoryLength < 24 {
			issues = append(issues, fmt.Sprintf("History: %d (recommended: 24+)", domain.PwdHistoryLength))
		}
	}

	// Check GPO password policies
	for _, gpo := range snapshot.GPOs {
		if gpo.PasswordPolicy == nil || !gpo.IsLinked {
			continue
		}
		pp := gpo.PasswordPolicy
		gpoIssues := []string{}
		if pp.MinPasswordLength < 14 {
			gpoIssues = append(gpoIssues, fmt.Sprintf("length<%d", pp.MinPasswordLength))
		}
		if !pp.ComplexityEnabled {
			gpoIssues = append(gpoIssues, "complexity=off")
		}
		if pp.ReversibleEncryption {
			gpoIssues = append(gpoIssues, "reversible=on")
		}
		if len(gpoIssues) > 0 {
			affected = append(affected, types.AffectedObject{
				Type:   "GPO",
				Name:   gpo.Name,
				Detail: fmt.Sprintf("Weak policy: %v", gpoIssues),
			})
		}
	}

	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("G002")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "G002",
		Name:            ind.Name,
		Description:     fmt.Sprintf("Weak password policy detected. Issues: %v", issues),
		Severity:        types.SeverityMedium,
		Category:        types.CategoryGroupPolicy,
		RiskScore:       30 + len(affected)*5,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkSYSVOLPermissions(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, gpo := range snapshot.GPOs {
		if gpo.SYSVOLWritable {
			affected = append(affected, types.AffectedObject{
				Type:   "GPO",
				Name:   gpo.Name,
				Detail: fmt.Sprintf("SYSVOL path for GPO %s is writable by non-admins", gpo.ID),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("G003")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "G003",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d GPO SYSVOL path(s) are writable by non-administrative accounts. Malicious scripts in SYSVOL execute on all domain machines.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryGroupPolicy,
		RiskScore:       60,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkOrphanedGPOs(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, gpo := range snapshot.GPOs {
		if !gpo.IsLinked {
			affected = append(affected, types.AffectedObject{
				Type:   "GPO",
				Name:   gpo.Name,
				Detail: fmt.Sprintf("GUID: %s | Modified: %s", gpo.ID, gpo.Modified.Format("2006-01-02")),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("G004")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "G004",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d GPO(s) are not linked to any OU. Orphaned GPOs are administrative clutter and may contain sensitive settings.", len(affected)),
		Severity:        types.SeverityLow,
		Category:        types.CategoryGroupPolicy,
		RiskScore:       5,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkWDigestViaGPO(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, gpo := range snapshot.GPOs {
		if gpo.SecuritySettings != nil && gpo.SecuritySettings.WDigestAuthentication && gpo.IsLinked {
			affected = append(affected, types.AffectedObject{
				Type:   "GPO",
				Name:   gpo.Name,
				Detail: "Sets WDigest UseLogonCredential=1 (cleartext passwords in LSASS)",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("G005")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "G005",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d GPO(s) enable WDigest authentication, causing credentials to be stored in cleartext in LSASS memory.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryGroupPolicy,
		RiskScore:       65,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}
