package indicators

import (
	"fmt"
	"strings"
	"time"

	"ad-assessment/shared/types"
)

// CheckAdvanced runs the indicators that don't fit neatly into existing categories
// but are essential for a best-in-class assessment: shadow credentials, machine
// account quota, recycle bin, inactive computers, RC4, NTLMv1.
func CheckAdvanced(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding
	findings = append(findings, checkMachineAccountQuota(snapshot, scanID)...)
	findings = append(findings, checkRecycleBin(snapshot, scanID)...)
	findings = append(findings, checkInactiveComputers(snapshot, scanID)...)
	findings = append(findings, checkRC4Enabled(snapshot, scanID)...)
	findings = append(findings, checkShadowCredentials(snapshot, scanID)...)
	findings = append(findings, checkNTLMv1(snapshot, scanID)...)
	return findings
}

func checkMachineAccountQuota(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	if snapshot.MachineAccountQuota == 0 {
		return nil
	}
	ind := findIndicator("S006")
	return []types.Finding{{
		ScanID:      scanID,
		IndicatorID: "S006",
		Name:        ind.Name,
		Description: fmt.Sprintf("ms-DS-MachineAccountQuota is set to %d. Any authenticated user can join that many computers to the domain, enabling RBCD and Kerberos relay attacks.", snapshot.MachineAccountQuota),
		Severity:    types.SeverityMedium,
		Category:    types.CategoryADStructure,
		RiskScore:   30,
		AffectedObjects: []types.AffectedObject{
			{Type: "Domain", Name: "Domain Policy", Detail: fmt.Sprintf("ms-DS-MachineAccountQuota = %d", snapshot.MachineAccountQuota)},
		},
		Remediation: ind.Remediation,
		References:  ind.References,
		MITRE:       ind.MITRE,
	}}
}

func checkRecycleBin(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	if snapshot.RecycleBinEnabled {
		return nil
	}
	ind := findIndicator("S005")
	return []types.Finding{{
		ScanID:      scanID,
		IndicatorID: "S005",
		Name:        ind.Name,
		Description: "The Active Directory Recycle Bin is not enabled. Deleted objects cannot be restored without a full AD backup restore, and an attacker can permanently remove accounts or GPOs.",
		Severity:    types.SeverityLow,
		Category:    types.CategoryADStructure,
		RiskScore:   12,
		AffectedObjects: []types.AffectedObject{
			{Type: "Forest", Name: "AD Forest", Detail: "Recycle Bin optional feature not enabled"},
		},
		Remediation: ind.Remediation,
		References:  ind.References,
		MITRE:       ind.MITRE,
	}}
}

func checkInactiveComputers(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	threshold := time.Now().AddDate(0, 0, -90)
	var affected []types.AffectedObject
	for _, comp := range snapshot.Computers {
		if !comp.Enabled || comp.IsDomainController {
			continue
		}
		lastSeen := comp.LastLogonTimestamp
		if lastSeen.IsZero() {
			lastSeen = comp.LastLogon
		}
		if !lastSeen.IsZero() && lastSeen.Before(threshold) {
			days := int(time.Since(lastSeen).Hours() / 24)
			affected = append(affected, types.AffectedObject{
				DN:     comp.DistinguishedName,
				Type:   "Computer",
				Name:   comp.Name,
				Detail: fmt.Sprintf("Last seen: %s (%d days ago) | OS: %s", lastSeen.Format("2006-01-02"), days, comp.OperatingSystem),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("S007")
	severity := types.SeverityLow
	if len(affected) > 20 {
		severity = types.SeverityMedium
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "S007",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d computer account(s) have not authenticated in over 90 days but remain enabled. These stale accounts increase the attack surface.", len(affected)),
		Severity:        severity,
		Category:        types.CategoryADStructure,
		RiskScore:       min(40, 5+len(affected)),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkRC4Enabled(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	if snapshot.KerberosConfig == nil {
		return nil
	}
	if !snapshot.KerberosConfig.RC4Enabled {
		return nil
	}
	ind := findIndicator("N001")
	return []types.Finding{{
		ScanID:      scanID,
		IndicatorID: "N001",
		Name:        ind.Name,
		Description: "RC4-HMAC Kerberos encryption is permitted in this domain. Kerberoastable service tickets encrypted with RC4 can be cracked significantly faster than AES-encrypted tickets.",
		Severity:    types.SeverityMedium,
		Category:    types.CategoryNTLM,
		RiskScore:   25,
		AffectedObjects: []types.AffectedObject{
			{Type: "Domain", Name: snapshot.KerberosConfig.Domain, Detail: "RC4-HMAC enabled in msDS-SupportedEncryptionTypes"},
		},
		Remediation: ind.Remediation,
		References:  ind.References,
		MITRE:       ind.MITRE,
	}}
}

func checkShadowCredentials(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	// Look for KeyCredentialLink attribute on privileged accounts
	// We detect this by checking for non-empty ShadowCredentials field in user data
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if !user.IsPrivileged {
			continue
		}
		if user.HasShadowCredentials {
			affected = append(affected, types.AffectedObject{
				DN:     user.DistinguishedName,
				Type:   "User",
				Name:   user.SamAccountName,
				Detail: fmt.Sprintf("msDS-KeyCredentialLink set | Groups: %s", strings.Join(user.PrivilegedGroups, ", ")),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("N002")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "N002",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d privileged account(s) have msDS-KeyCredentialLink populated. This could represent a persistence backdoor planted by an attacker to maintain access via certificate-based authentication.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPersistence,
		RiskScore:       90,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkNTLMv1(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	// Check GPO security settings for LM auth level
	for _, gpo := range snapshot.GPOs {
		if gpo.SecuritySettings == nil {
			continue
		}
		if gpo.SecuritySettings.LMAuthenticationLevel < 3 {
			ind := findIndicator("N003")
			return []types.Finding{{
				ScanID:      scanID,
				IndicatorID: "N003",
				Name:        ind.Name,
				Description: fmt.Sprintf("LAN Manager Authentication Level is set to %d (allows NTLMv1/LM responses). NTLMv1 handshakes can be cracked offline or relayed to authenticate as the victim.", gpo.SecuritySettings.LMAuthenticationLevel),
				Severity:    types.SeverityHigh,
				Category:    types.CategoryNTLM,
				RiskScore:   60,
				AffectedObjects: []types.AffectedObject{
					{Type: "GPO", Name: gpo.DisplayName, Detail: fmt.Sprintf("LmCompatibilityLevel = %d", gpo.SecuritySettings.LMAuthenticationLevel)},
				},
				Remediation: ind.Remediation,
				References:  ind.References,
				MITRE:       ind.MITRE,
			}}
		}
	}
	return nil
}
