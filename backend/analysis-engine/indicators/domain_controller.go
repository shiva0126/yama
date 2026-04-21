package indicators

import (
	"fmt"
	"strings"

	"ad-assessment/shared/types"
)

// CheckDomainControllers runs DC-specific security indicators
func CheckDomainControllers(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding

	findings = append(findings, checkOutdatedDCOS(snapshot, scanID)...)
	findings = append(findings, checkPrintSpoolerOnDC(snapshot, scanID)...)
	findings = append(findings, checkSMBSigningOnDC(snapshot, scanID)...)
	findings = append(findings, checkLDAPSigning(snapshot, scanID)...)

	return findings
}

func checkOutdatedDCOS(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, dc := range snapshot.DomainControllers {
		if isOutdatedOS(dc.OperatingSystem, dc.OSVersion) {
			affected = append(affected, types.AffectedObject{
				DN:     dc.HostName,
				Type:   "DomainController",
				Name:   dc.Name,
				Detail: fmt.Sprintf("OS: %s %s", dc.OperatingSystem, dc.OSVersion),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("DC001")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "DC001",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d DC(s) running outdated/EOL OS. Outdated DCs miss security patches and modern defenses.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryDomainControllers,
		RiskScore:       50 + len(affected)*5,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkPrintSpoolerOnDC(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, dc := range snapshot.DomainControllers {
		if dc.SpoolerRunning {
			affected = append(affected, types.AffectedObject{
				Type:   "DomainController",
				Name:   dc.Name,
				Detail: fmt.Sprintf("Print Spooler service running on %s (%s)", dc.Name, dc.IPAddress),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("DC002")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "DC002",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d DC(s) have the Print Spooler service running. This enables PrintNightmare (CVE-2021-1675) and coerced authentication attacks.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryDomainControllers,
		RiskScore:       min(100, 60+len(affected)*10),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkSMBSigningOnDC(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, dc := range snapshot.DomainControllers {
		if !dc.SMBSigningRequired {
			affected = append(affected, types.AffectedObject{
				Type:   "DomainController",
				Name:   dc.Name,
				Detail: fmt.Sprintf("SMB signing not required | IP: %s", dc.IPAddress),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("DC003")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "DC003",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d DC(s) do not require SMB signing, enabling SMB relay attacks (NTLM relay to DC).", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryDomainControllers,
		RiskScore:       50 + len(affected)*5,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkLDAPSigning(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, dc := range snapshot.DomainControllers {
		if !dc.LDAPSigningRequired {
			affected = append(affected, types.AffectedObject{
				Type:   "DomainController",
				Name:   dc.Name,
				Detail: fmt.Sprintf("LDAP signing not required | IP: %s", dc.IPAddress),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("DC004")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "DC004",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d DC(s) do not require LDAP signing, enabling LDAP relay attacks.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryDomainControllers,
		RiskScore:       45 + len(affected)*5,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func isOutdatedOS(os, version string) bool {
	lowerOS := strings.ToLower(os)
	// Flag anything below Server 2016
	outdatedKeywords := []string{
		"2003", "2008", "2012",
		"windows nt", "windows 2000",
	}
	for _, kw := range outdatedKeywords {
		if strings.Contains(lowerOS, kw) {
			// Exception: 2012 R2 is still common but EOL - flag it
			return true
		}
	}
	return false
}
