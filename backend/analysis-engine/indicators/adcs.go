package indicators

import (
	"fmt"
	"strings"

	"ad-assessment/shared/types"
)

// CheckPKI runs all ADCS / certificate services indicators (ESC1–ESC15).
func CheckPKI(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding
	findings = append(findings, checkESC1(snapshot, scanID)...)
	findings = append(findings, checkESC2(snapshot, scanID)...)
	findings = append(findings, checkESC3(snapshot, scanID)...)
	findings = append(findings, checkESC4(snapshot, scanID)...)
	findings = append(findings, checkESC6(snapshot, scanID)...)
	findings = append(findings, checkESC7(snapshot, scanID)...)
	findings = append(findings, checkESC8(snapshot, scanID)...)
	findings = append(findings, checkESC9(snapshot, scanID)...)
	findings = append(findings, checkESC10(snapshot, scanID)...)
	findings = append(findings, checkESC11(snapshot, scanID)...)
	findings = append(findings, checkESC12(snapshot, scanID)...)
	findings = append(findings, checkESC13(snapshot, scanID)...)
	findings = append(findings, checkESC15(snapshot, scanID)...)
	return findings
}

// ESC8: NTLM relay to ADCS HTTP enrollment endpoint.
func checkESC8(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, ca := range snapshot.CertAuthorities {
		if ca.WebEnrollmentEnabled {
			affected = append(affected, types.AffectedObject{
				Type:   "CertificateAuthority",
				Name:   ca.Name,
				DN:     ca.DistinguishedName,
				Detail: "Web enrollment HTTP endpoint is active — vulnerable to NTLM relay attacks (certifried, Responder + ntlmrelayx)",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI008",
		Name:            "ADCS ESC8 — NTLM Relay to HTTP Enrollment",
		Description:     fmt.Sprintf("%d CA(s) have the HTTP certificate enrollment web service active without Extended Protection for Authentication, enabling NTLM relay to obtain certificates for arbitrary domain accounts.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPKI,
		RiskScore:       90,
		AffectedObjects: affected,
		Remediation:     "Enforce Extended Protection for Authentication (EPA) on the certsrv virtual directory and disable HTTP enrollment in favour of HTTPS with client certificate binding.",
		References:      []string{"https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
		MITRE:           []string{"T1557.001", "T1649"},
	}}
}

// ESC9: CT_FLAG_NO_SECURITY_EXTENSION set — security extension not embedded in issued certs.
func checkESC9(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, t := range snapshot.CertTemplates {
		if t.VulnerableESC9 {
			affected = append(affected, types.AffectedObject{
				Type:   "CertTemplate",
				Name:   t.DisplayName,
				DN:     t.DistinguishedName,
				Detail: "CT_FLAG_NO_SECURITY_EXTENSION (0x80000) — security SID extension omitted from issued certificates",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI009",
		Name:            "ADCS ESC9 — No Security Extension in Certificate",
		Description:     fmt.Sprintf("%d template(s) have CT_FLAG_NO_SECURITY_EXTENSION set. Certificates issued from these templates do not embed the security SID, allowing certificate-based authentication bypass under certain mapping policies.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryPKI,
		RiskScore:       75,
		AffectedObjects: affected,
		Remediation:     "Remove CT_FLAG_NO_SECURITY_EXTENSION from the msPKI-Certificate-Name-Flag attribute and ensure StrongCertificateBindingEnforcement = 2 on all DCs.",
		References:      []string{"https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7"},
		MITRE:           []string{"T1649"},
	}}
}

// ESC10: Weak certificate mapping — SAN-based mapping accepted by DCs.
func checkESC10(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, dc := range snapshot.DomainControllers {
		if !dc.LDAPSigningRequired || dc.WDigestEnabled {
			affected = append(affected, types.AffectedObject{
				Type:   "DomainController",
				Name:   dc.Name,
				DN:     dc.HostName,
				Detail: "Weak authentication transport settings detected — ESC10 exploitation feasible",
			})
		}
	}
	for _, t := range snapshot.CertTemplates {
		if t.VulnerableESC10 {
			affected = append(affected, types.AffectedObject{
				Type:   "CertTemplate",
				Name:   t.DisplayName,
				DN:     t.DistinguishedName,
				Detail: "Template enrolled with weak subject mapping accepted by DCs",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI010",
		Name:            "ADCS ESC10 — Weak Certificate Mapping Policy",
		Description:     fmt.Sprintf("Certificate mapping policy allows SAN-based identity assertion. An attacker who controls a certificate with a forged SAN can authenticate as any domain account. Affects %d object(s).", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPKI,
		RiskScore:       88,
		AffectedObjects: affected,
		Remediation:     "Set StrongCertificateBindingEnforcement = 2 on all DCs (KB5014754). Ensure CertificateMappingMethods does not include bit 4 (UPN-SAN mapping).",
		References:      []string{"https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16"},
		MITRE:           []string{"T1649"},
	}}
}

// ESC11: ADCS does not enforce request encryption (IF_ENFORCEENCRYPTICERTREQUEST = 0).
func checkESC11(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, ca := range snapshot.CertAuthorities {
		if ca.RequestEncryptionDisabled {
			affected = append(affected, types.AffectedObject{
				Type:   "CertificateAuthority",
				Name:   ca.Name,
				DN:     ca.DistinguishedName,
				Detail: "IF_ENFORCEENCRYPTICERTREQUEST is not set — certificate requests can be relayed without encryption",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI011",
		Name:            "ADCS ESC11 — Certificate Request Encryption Not Enforced",
		Description:     fmt.Sprintf("%d CA(s) do not enforce encrypted certificate request transport. This allows NTLM relay of RPC-based enrollment requests (ICertPassage interface).", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryPKI,
		RiskScore:       70,
		AffectedObjects: affected,
		Remediation:     "Set IF_ENFORCEENCRYPTICERTREQUEST on the CA flags attribute and enable HTTPS for all enrollment interfaces.",
		References:      []string{"https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-ESC11"},
		MITRE:           []string{"T1557.001", "T1649"},
	}}
}

// ESC12: CA operator shell access — CA runs as SYSTEM and operator has shell.
func checkESC12(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, ca := range snapshot.CertAuthorities {
		if ca.ShellAccessEnabled {
			affected = append(affected, types.AffectedObject{
				Type:   "CertificateAuthority",
				Name:   ca.Name,
				DN:     ca.DistinguishedName,
				Detail: "CA running on a host where a low-privilege account has interactive/RDP/shell access — SYSTEM escalation via certutil or CA service",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI012",
		Name:            "ADCS ESC12 — CA Shell Access Escalation Path",
		Description:     fmt.Sprintf("%d CA host(s) allow shell access to accounts without CA administrative rights. Because the CA service runs as SYSTEM, local code execution can yield complete CA compromise.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryPKI,
		RiskScore:       72,
		AffectedObjects: affected,
		Remediation:     "Restrict interactive logon to CA hosts to CA administrators only. Enable AppLocker or WDAC to prevent arbitrary code execution on the CA host.",
		References:      []string{"https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-ESC12"},
		MITRE:           []string{"T1649", "T1078"},
	}}
}

// ESC13: OID group link — issuance policy OID grants group membership.
func checkESC13(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, t := range snapshot.CertTemplates {
		if t.VulnerableESC13 && t.LowPrivEnrollment {
			detail := "Template has OID group link"
			if t.OIDGroupLink != "" {
				detail += ": " + t.OIDGroupLink
			}
			affected = append(affected, types.AffectedObject{
				Type:   "CertTemplate",
				Name:   t.DisplayName,
				DN:     t.DistinguishedName,
				Detail: detail,
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI013",
		Name:            "ADCS ESC13 — OID Group Link Privilege Escalation",
		Description:     fmt.Sprintf("%d template(s) have an issuance policy OID linked to a privileged group. Enrolling in the template implicitly grants group membership upon authentication, allowing privilege escalation.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPKI,
		RiskScore:       85,
		AffectedObjects: affected,
		Remediation:     "Remove OID group links from templates accessible to low-privilege users. Audit all msDS-OIDToGroupLink attribute values on issuance policies.",
		References:      []string{"https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53"},
		MITRE:           []string{"T1649", "T1484"},
	}}
}

// ESC15: Schema version 1 template — application policies bypass EKU restrictions.
func checkESC15(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, t := range snapshot.CertTemplates {
		if t.VulnerableESC15 && t.LowPrivEnrollment {
			affected = append(affected, types.AffectedObject{
				Type:   "CertTemplate",
				Name:   t.DisplayName,
				DN:     t.DistinguishedName,
				Detail: fmt.Sprintf("Schema version %d — application policies in request can override EKU for client auth", t.SchemaVersion),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "PKI015",
		Name:            "ADCS ESC15 — Schema V1 Application Policy EKU Override",
		Description:     fmt.Sprintf("%d schema-version-1 template(s) are enrollable by low-privilege users. Attackers can add Application Policies to the certificate request that override the template's EKU, obtaining a client-authentication certificate regardless of the template's intended purpose.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryPKI,
		RiskScore:       78,
		AffectedObjects: affected,
		Remediation:     "Upgrade templates to schema version 2+ or restrict enrollment to privileged accounts. Validate msPKI-RA-Application-Policies on published templates.",
		References:      []string{"https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-ESC15"},
		MITRE:           []string{"T1649"},
	}}
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
