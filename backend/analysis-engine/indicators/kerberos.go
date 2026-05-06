package indicators

import (
	"fmt"
	"time"

	"ad-assessment/shared/types"
)

// CheckKerberos runs all Kerberos-related security indicators
func CheckKerberos(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding

	findings = append(findings, checkKrbtgtPasswordAge(snapshot, scanID)...)
	findings = append(findings, checkASREPRoastable(snapshot, scanID)...)
	findings = append(findings, checkKerberoastable(snapshot, scanID)...)
	findings = append(findings, checkDESEnabled(snapshot, scanID)...)
	findings = append(findings, checkConstrainedDelegationWithProtocolTransition(snapshot, scanID)...)

	return findings
}

func checkKrbtgtPasswordAge(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	if snapshot.KerberosConfig == nil {
		return nil
	}
	kc := snapshot.KerberosConfig
	if kc.KrbtgtPasswordLastSet.IsZero() {
		return nil
	}

	ageDays := int(time.Since(kc.KrbtgtPasswordLastSet).Hours() / 24)
	if ageDays < 180 {
		return nil
	}

	indicator := findIndicator("K001")
	f := types.Finding{
		ScanID:      scanID,
		IndicatorID: "K001",
		Name:        indicator.Name,
		Description: fmt.Sprintf("The krbtgt account password was last reset %d days ago (threshold: 180 days). Last set: %s",
			ageDays, kc.KrbtgtPasswordLastSet.Format("2006-01-02")),
		Severity:    types.SeverityCritical,
		Category:    types.CategoryKerberos,
		RiskScore:   calculateRiskScore(types.SeverityCritical, ageDays, 180, 730),
		Remediation: indicator.Remediation,
		References:  indicator.References,
		MITRE:       indicator.MITRE,
		AffectedObjects: []types.AffectedObject{
			{Type: "Domain", Name: snapshot.KerberosConfig.Domain, Detail: fmt.Sprintf("krbtgt last reset: %d days ago", ageDays)},
		},
	}
	return []types.Finding{f}
}

func checkASREPRoastable(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if user.DontRequirePreauth && user.Enabled {
			affected = append(affected, types.AffectedObject{
				DN:     user.DistinguishedName,
				Type:   "User",
				Name:   user.SamAccountName,
				Detail: fmt.Sprintf("UPN: %s | Last Logon: %s", user.UserPrincipalName, user.LastLogon.Format("2006-01-02")),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	indicator := findIndicator("K003")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "K003",
		Name:            indicator.Name,
		Description:     fmt.Sprintf("%d user account(s) have Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH), making them vulnerable to AS-REP Roasting.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryKerberos,
		RiskScore:       min(100, 30+len(affected)*10),
		AffectedObjects: affected,
		Remediation:     indicator.Remediation,
		References:      indicator.References,
		MITRE:           indicator.MITRE,
	}}
}

func checkKerberoastable(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if len(user.ServicePrincipalNames) > 0 && user.Enabled && !user.IsMSA && !user.IsGMSA {
			// Exclude computer accounts (they have $ suffix)
			if len(user.SamAccountName) > 0 && user.SamAccountName[len(user.SamAccountName)-1] != '$' {
				spnsDetail := ""
				for i, spn := range user.ServicePrincipalNames {
					if i > 0 {
						spnsDetail += ", "
					}
					spnsDetail += spn
					if i >= 2 {
						spnsDetail += fmt.Sprintf(" (+%d more)", len(user.ServicePrincipalNames)-3)
						break
					}
				}
				affected = append(affected, types.AffectedObject{
					DN:     user.DistinguishedName,
					Type:   "User",
					Name:   user.SamAccountName,
					Detail: "SPNs: " + spnsDetail,
				})
			}
		}
	}
	if len(affected) == 0 {
		return nil
	}
	indicator := findIndicator("K004")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "K004",
		Name:            indicator.Name,
		Description:     fmt.Sprintf("%d user account(s) with SPNs can be targeted with Kerberoasting to obtain offline-crackable service ticket hashes.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryKerberos,
		RiskScore:       min(100, 25+len(affected)*8),
		AffectedObjects: affected,
		Remediation:     indicator.Remediation,
		References:      indicator.References,
		MITRE:           indicator.MITRE,
	}}
}

func checkDESEnabled(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if user.UseDesKeyOnly && user.Enabled {
			affected = append(affected, types.AffectedObject{
				DN:   user.DistinguishedName,
				Type: "User",
				Name: user.SamAccountName,
			})
		}
	}
	// Also check computers
	for _, comp := range snapshot.Computers {
		// UAC flag 0x200000 = USE_DES_KEY_ONLY
		if comp.UserAccountControl&0x200000 != 0 && comp.Enabled {
			affected = append(affected, types.AffectedObject{
				DN:   comp.DistinguishedName,
				Type: "Computer",
				Name: comp.Name,
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}

	// Also check if DES is globally enabled
	globalDES := snapshot.KerberosConfig != nil && snapshot.KerberosConfig.DESEnabled

	indicator := findIndicator("K005")
	desc := fmt.Sprintf("%d account(s) have DES-only Kerberos encryption enabled.", len(affected))
	if globalDES {
		desc += " Additionally, DES is globally enabled in the domain Kerberos configuration."
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "K005",
		Name:            indicator.Name,
		Description:     desc,
		Severity:        types.SeverityMedium,
		Category:        types.CategoryKerberos,
		RiskScore:       min(100, 20+len(affected)*5),
		AffectedObjects: affected,
		Remediation:     indicator.Remediation,
		References:      indicator.References,
		MITRE:           indicator.MITRE,
	}}
}

func checkConstrainedDelegationWithProtocolTransition(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if user.TrustedToAuthForDelegation && len(user.AllowedToDelegateTo) > 0 {
			affected = append(affected, types.AffectedObject{
				DN:     user.DistinguishedName,
				Type:   "User",
				Name:   user.SamAccountName,
				Detail: fmt.Sprintf("Delegates to: %v", user.AllowedToDelegateTo),
			})
		}
	}
	for _, comp := range snapshot.Computers {
		if comp.TrustedToAuthForDelegation && len(comp.AllowedToDelegateTo) > 0 && !comp.IsDomainController {
			affected = append(affected, types.AffectedObject{
				DN:     comp.DistinguishedName,
				Type:   "Computer",
				Name:   comp.Name,
				Detail: fmt.Sprintf("Delegates to: %v", comp.AllowedToDelegateTo),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	indicator := findIndicator("K006")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "K006",
		Name:            indicator.Name,
		Description:     fmt.Sprintf("%d account(s) have constrained delegation with protocol transition (S4U2Self), allowing impersonation of any user to configured services.", len(affected)),
		Severity:        types.SeverityMedium,
		Category:        types.CategoryKerberos,
		RiskScore:       min(100, 15+len(affected)*8),
		AffectedObjects: affected,
		Remediation:     indicator.Remediation,
		References:      indicator.References,
		MITRE:           indicator.MITRE,
	}}
}

// ============================================================
// Helpers
// ============================================================

func findIndicator(id string) types.SecurityIndicator {
	for _, ind := range types.AllIndicators {
		if ind.ID == id {
			return ind
		}
	}
	return types.SecurityIndicator{ID: id}
}

// calculateRiskScore scales between min/max severity range
func calculateRiskScore(severity types.Severity, value, minBad, maxBad int) int {
	base := severity.Score() * 2
	if value <= minBad {
		return base
	}
	extra := (value - minBad) * 30 / (maxBad - minBad)
	score := base + extra
	if score > 100 {
		return 100
	}
	return score
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
