package indicators

import (
	"fmt"
	"time"

	"ad-assessment/shared/types"
)

// CheckAccounts runs all account security indicators
func CheckAccounts(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding

	findings = append(findings, checkPasswordNeverExpires(snapshot, scanID)...)
	findings = append(findings, checkReversibleEncryption(snapshot, scanID)...)
	findings = append(findings, checkStaleAccounts(snapshot, scanID)...)
	findings = append(findings, checkPasswordNotRequired(snapshot, scanID)...)
	findings = append(findings, checkPrivilegedPasswordNeverExpires(snapshot, scanID)...)
	findings = append(findings, checkDefaultAdminEnabled(snapshot, scanID)...)
	findings = append(findings, checkGuestEnabled(snapshot, scanID)...)

	return findings
}

func checkPasswordNeverExpires(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if user.PasswordNeverExpires && user.Enabled && !user.IsMSA && !user.IsGMSA {
			detail := ""
			if user.PwdLastSet.IsZero() {
				detail = "Password never set"
			} else {
				days := int(time.Since(user.PwdLastSet).Hours() / 24)
				detail = fmt.Sprintf("Password last changed: %d days ago", days)
			}
			affected = append(affected, types.AffectedObject{
				DN:     user.DistinguishedName,
				Type:   "User",
				Name:   user.SamAccountName,
				Detail: detail,
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("A001")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "A001",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d user account(s) have the 'Password Never Expires' flag set. These passwords may be very old and weak.", len(affected)),
		Severity:        types.SeverityMedium,
		Category:        types.CategoryAccounts,
		RiskScore:       min(100, 15+len(affected)*2),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkReversibleEncryption(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if user.ReversibleEncryption && user.Enabled {
			affected = append(affected, types.AffectedObject{
				DN:   user.DistinguishedName,
				Type: "User",
				Name: user.SamAccountName,
			})
		}
	}
	// Also check GPO setting
	for _, gpo := range snapshot.GPOs {
		if gpo.PasswordPolicy != nil && gpo.PasswordPolicy.ReversibleEncryption {
			affected = append(affected, types.AffectedObject{
				Type:   "GPO",
				Name:   gpo.Name,
				Detail: "GPO sets 'Store passwords using reversible encryption'",
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("A002")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "A002",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d account(s) use reversible password encryption. Passwords can be decrypted directly from NTDS.dit.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryAccounts,
		RiskScore:       min(100, 40+len(affected)*5),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkStaleAccounts(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	threshold := time.Now().AddDate(0, 0, -90)
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if !user.Enabled {
			continue
		}
		// Skip service accounts (gMSA/MSA) and system accounts
		if user.IsGMSA || user.IsMSA {
			continue
		}
		// Check both LastLogon and LastLogonTimestamp (timestamp replicates, logon may not)
		lastActivity := user.LastLogonTimestamp
		if user.LastLogon.After(lastActivity) {
			lastActivity = user.LastLogon
		}
		if !lastActivity.IsZero() && lastActivity.Before(threshold) {
			days := int(time.Since(lastActivity).Hours() / 24)
			affected = append(affected, types.AffectedObject{
				DN:     user.DistinguishedName,
				Type:   "User",
				Name:   user.SamAccountName,
				Detail: fmt.Sprintf("Last logon: %d days ago (%s)", days, lastActivity.Format("2006-01-02")),
			})
		} else if lastActivity.IsZero() {
			// Never logged in - also stale if created more than 90 days ago
			if user.Created.Before(threshold) {
				affected = append(affected, types.AffectedObject{
					DN:     user.DistinguishedName,
					Type:   "User",
					Name:   user.SamAccountName,
					Detail: fmt.Sprintf("Never logged in (created: %s)", user.Created.Format("2006-01-02")),
				})
			}
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("A003")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "A003",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d enabled user account(s) have not logged in for over 90 days. These are likely orphaned accounts.", len(affected)),
		Severity:        types.SeverityMedium,
		Category:        types.CategoryAccounts,
		RiskScore:       min(100, 10+len(affected)*2),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkPasswordNotRequired(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if user.PasswordNotRequired && user.Enabled {
			affected = append(affected, types.AffectedObject{
				DN:   user.DistinguishedName,
				Type: "User",
				Name: user.SamAccountName,
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("A004")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "A004",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d account(s) have PASSWD_NOTREQD flag set, potentially allowing empty passwords.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryAccounts,
		RiskScore:       min(100, 30+len(affected)*8),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkPrivilegedPasswordNeverExpires(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject
	for _, user := range snapshot.Users {
		if user.PasswordNeverExpires && user.Enabled && user.IsPrivileged {
			days := 0
			if !user.PwdLastSet.IsZero() {
				days = int(time.Since(user.PwdLastSet).Hours() / 24)
			}
			affected = append(affected, types.AffectedObject{
				DN:     user.DistinguishedName,
				Type:   "User",
				Name:   user.SamAccountName,
				Detail: fmt.Sprintf("Privileged groups: %v | Pwd age: %d days", user.PrivilegedGroups, days),
			})
		}
	}
	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("A005")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "A005",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d privileged account(s) have non-expiring passwords. These high-value accounts require strict password rotation.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryAccounts,
		RiskScore:       min(100, 40+len(affected)*10),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkDefaultAdminEnabled(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	for _, user := range snapshot.Users {
		// RID 500 = built-in Administrator
		if isRID500(user.ObjectSID) && user.Enabled {
			pwdAge := 0
			if !user.PwdLastSet.IsZero() {
				pwdAge = int(time.Since(user.PwdLastSet).Hours() / 24)
			}
			ind := findIndicator("A006")
			return []types.Finding{{
				ScanID:      scanID,
				IndicatorID: "A006",
				Name:        ind.Name,
				Description: fmt.Sprintf("Built-in Administrator account (RID-500) '%s' is enabled. Password age: %d days.", user.SamAccountName, pwdAge),
				Severity:    types.SeverityMedium,
				Category:    types.CategoryAccounts,
				RiskScore:   25,
				AffectedObjects: []types.AffectedObject{
					{DN: user.DistinguishedName, Type: "User", Name: user.SamAccountName, Detail: fmt.Sprintf("RID-500 | Pwd age: %d days", pwdAge)},
				},
				Remediation: ind.Remediation,
				References:  ind.References,
				MITRE:       ind.MITRE,
			}}
		}
	}
	return nil
}

func checkGuestEnabled(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	for _, user := range snapshot.Users {
		if isRID501(user.ObjectSID) && user.Enabled {
			ind := findIndicator("A007")
			return []types.Finding{{
				ScanID:      scanID,
				IndicatorID: "A007",
				Name:        ind.Name,
				Description: fmt.Sprintf("Built-in Guest account '%s' is enabled, allowing unauthenticated access.", user.SamAccountName),
				Severity:    types.SeverityHigh,
				Category:    types.CategoryAccounts,
				RiskScore:   50,
				AffectedObjects: []types.AffectedObject{
					{DN: user.DistinguishedName, Type: "User", Name: user.SamAccountName, Detail: "RID-501 Guest account"},
				},
				Remediation: ind.Remediation,
				References:  ind.References,
				MITRE:       ind.MITRE,
			}}
		}
	}
	return nil
}

// isRID500 checks if SID ends with -500 (built-in Administrator)
func isRID500(sid string) bool {
	if len(sid) < 4 {
		return false
	}
	return sid[len(sid)-4:] == "-500"
}

// isRID501 checks if SID ends with -501 (Guest)
func isRID501(sid string) bool {
	if len(sid) < 4 {
		return false
	}
	return sid[len(sid)-4:] == "-501"
}
