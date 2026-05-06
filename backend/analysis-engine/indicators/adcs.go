package indicators

import (
	"fmt"
	"strings"

	"ad-assessment/shared/types"
)

// CheckPKI runs all ADCS / certificate services indicators.
func CheckPKI(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding
	findings = append(findings, checkESC1(snapshot, scanID)...)
	findings = append(findings, checkESC2(snapshot, scanID)...)
	findings = append(findings, checkESC3(snapshot, scanID)...)
	findings = append(findings, checkESC4(snapshot, scanID)...)
	findings = append(findings, checkESC6(snapshot, scanID)...)
	findings = append(findings, checkESC7(snapshot, scanID)...)
	return findings
}

func checkESC1(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, t := range snapshot.CertTemplates {
		if t.VulnerableESC1 {
			affected = append(affected, types.AffectedObject{
				DN:     t.DistinguishedName,
				Type:   "CertTemplate",
				Name:   t.DisplayName,
				Detail: fmt.Sprintf("EKU: %s | Low-priv enroll: %v | SAN: %v", strings.Join(t.ExtendedKeyUsage, ","), t.LowPrivEnrollment, t.EnrolleeSuppliesSubject),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("PKI001")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI001",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d certificate template(s) allow low-privilege users to supply a Subject Alternative Name and authenticate with the issued certificate. Any domain user can impersonate Domain Admins.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPKI,
		RiskScore:       95,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkESC2(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, t := range snapshot.CertTemplates {
		if t.VulnerableESC2 {
			affected = append(affected, types.AffectedObject{
				DN:     t.DistinguishedName,
				Type:   "CertTemplate",
				Name:   t.DisplayName,
				Detail: fmt.Sprintf("EKU: %s | Any Purpose: %v", strings.Join(t.ExtendedKeyUsage, ","), t.HasAnyPurpose),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("PKI002")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI002",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d template(s) with Any Purpose EKU or no EKU restriction. Certificates issued from these templates can be used as a SubCA or for any authentication purpose.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPKI,
		RiskScore:       90,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkESC3(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, t := range snapshot.CertTemplates {
		if t.VulnerableESC3 {
			affected = append(affected, types.AffectedObject{
				DN:     t.DistinguishedName,
				Type:   "CertTemplate",
				Name:   t.DisplayName,
				Detail: "Certificate Request Agent EKU accessible to low-privilege users",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("PKI003")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI003",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d Certificate Request Agent template(s) accessible to low-privilege users. This allows enrollment on behalf of any domain user.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryPKI,
		RiskScore:       75,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkESC4(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, t := range snapshot.CertTemplates {
		if t.VulnerableESC4 {
			affected = append(affected, types.AffectedObject{
				DN:     t.DistinguishedName,
				Type:   "CertTemplate",
				Name:   t.DisplayName,
				Detail: fmt.Sprintf("Writable by: %s", strings.Join(t.WriteableBy, ", ")),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("PKI004")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI004",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d certificate template(s) have weak ACLs allowing low-privilege users to modify template settings, potentially introducing ESC1 conditions.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryPKI,
		RiskScore:       70,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkESC6(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, ca := range snapshot.CertAuthorities {
		if ca.UserSpecifiedSAN {
			affected = append(affected, types.AffectedObject{
				Type:   "CertificateAuthority",
				Name:   ca.Name,
				DN:     ca.DistinguishedName,
				Detail: "EDITF_ATTRIBUTESUBJECTALTNAME2 is set — any enrollable template can be used to supply a SAN",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("PKI005")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI005",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d Certificate Authority/ies have EDITF_ATTRIBUTESUBJECTALTNAME2 enabled. Any user who can enroll in any template can authenticate as any domain identity.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPKI,
		RiskScore:       95,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkESC7(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, ca := range snapshot.CertAuthorities {
		if ca.ManageCALowPriv {
			affected = append(affected, types.AffectedObject{
				Type:   "CertificateAuthority",
				Name:   ca.Name,
				DN:     ca.DistinguishedName,
				Detail: "Low-privilege accounts have ManageCA or ManageCertificates rights",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("PKI006")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI006",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d Certificate Authority/ies have over-permissive ACLs on the CA object, allowing privilege escalation through certificate approval or CA reconfiguration.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryPKI,
		RiskScore:       72,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}
