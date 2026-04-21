package indicators

import (
	"fmt"
	"strings"

	"ad-assessment/shared/types"
)

// CheckPrivilegedAccess runs privileged access indicators
func CheckPrivilegedAccess(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var findings []types.Finding

	findings = append(findings, checkDCSyncRights(snapshot, scanID)...)
	findings = append(findings, checkDomainAdminMembership(snapshot, scanID)...)
	findings = append(findings, checkSchemaAdminsNotEmpty(snapshot, scanID)...)
	findings = append(findings, checkEnterpriseAdmins(snapshot, scanID)...)
	findings = append(findings, checkAdminSDHolderDeviations(snapshot, scanID)...)
	findings = append(findings, checkGenericAllOnDomain(snapshot, scanID)...)

	return findings
}

func checkDCSyncRights(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject

	// DCSync requires DS-Replication-Get-Changes-All extended right on the domain object
	dcSyncRight := "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	replicationRight := "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"

	legitimatePrincipals := map[string]bool{
		"Domain Controllers":            true,
		"Enterprise Domain Controllers": true,
		"Enterprise Read-Only Domain Controllers": true,
		"Administrators":                true,
		"Domain Admins":                 true,
		"Enterprise Admins":             true,
		"SYSTEM":                        true,
	}

	for _, acl := range snapshot.ACLs {
		// Only check domain root object
		if !isDomainRootDN(acl.ObjectDN, snapshot.Domains) {
			continue
		}
		for _, entry := range acl.Entries {
			if entry.AccessType != "Allow" {
				continue
			}
			if entry.ObjectType != dcSyncRight && entry.ObjectType != replicationRight &&
				!strings.Contains(strings.ToLower(entry.Rights), "replication") {
				continue
			}
			// Check if trustee is a legitimate principal
			isLegitimate := false
			for legit := range legitimatePrincipals {
				if strings.Contains(entry.Trustee, legit) {
					isLegitimate = true
					break
				}
			}
			if !isLegitimate {
				affected = append(affected, types.AffectedObject{
					Type:   "ACL",
					Name:   entry.Trustee,
					Detail: fmt.Sprintf("Has replication right '%s' on domain root", entry.Rights),
				})
			}
		}
	}

	// Also check users flagged as DCSync capable
	for _, user := range snapshot.Users {
		if user.IsDCSyncCapable && !user.IsPrivileged {
			affected = append(affected, types.AffectedObject{
				DN:     user.DistinguishedName,
				Type:   "User",
				Name:   user.SamAccountName,
				Detail: "Non-privileged account with DCSync rights",
			})
		}
	}

	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("P001")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "P001",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d non-standard account(s) have DCSync rights (DS-Replication-Get-Changes-All), allowing complete credential dump of all domain accounts.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPrivileged,
		RiskScore:       min(100, 70+len(affected)*10),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkDomainAdminMembership(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject

	for _, group := range snapshot.Groups {
		if !isDomainAdminsGroup(group) {
			continue
		}
		for _, memberDN := range group.Members {
			// Resolve member
			member := findUserByDN(snapshot, memberDN)
			if member == nil {
				// Could be a computer or nested group — still flag
				affected = append(affected, types.AffectedObject{
					DN:   memberDN,
					Type: "Unknown",
					Name: extractCN(memberDN),
					Detail: "Member of Domain Admins",
				})
				continue
			}
			// Flag non-standard DA members (service accounts, stale accounts)
			detail := ""
			if member.IsServiceAccount {
				detail = "Service account - should not be in Domain Admins"
			} else if !member.Enabled {
				detail = "Disabled account still in Domain Admins"
			} else {
				detail = "Review if membership is authorized"
			}
			affected = append(affected, types.AffectedObject{
				DN:     member.DistinguishedName,
				Type:   "User",
				Name:   member.SamAccountName,
				Detail: detail,
			})
		}
		break
	}

	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("P002")
	severity := types.SeverityMedium
	if len(affected) > 5 {
		severity = types.SeverityHigh
	}
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "P002",
		Name:            ind.Name,
		Description:     fmt.Sprintf("Domain Admins group has %d member(s). Review all memberships and remove unnecessary accounts.", len(affected)),
		Severity:        severity,
		Category:        types.CategoryPrivileged,
		RiskScore:       min(100, 20+len(affected)*8),
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkSchemaAdminsNotEmpty(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	for _, group := range snapshot.Groups {
		if !isSchemaAdminsGroup(group) {
			continue
		}
		if len(group.Members) == 0 {
			return nil // Good - empty
		}
		var affected []types.AffectedObject
		for _, memberDN := range group.Members {
			affected = append(affected, types.AffectedObject{
				DN:   memberDN,
				Type: "Principal",
				Name: extractCN(memberDN),
				Detail: "Should only be in Schema Admins during schema modifications",
			})
		}
		ind := findIndicator("P003")
		return []types.Finding{{
			ScanID:          scanID,
			IndicatorID:     "P003",
			Name:            ind.Name,
			Description:     fmt.Sprintf("Schema Admins group has %d member(s). This group should be empty unless schema modifications are in progress.", len(affected)),
			Severity:        types.SeverityHigh,
			Category:        types.CategoryPrivileged,
			RiskScore:       40 + len(affected)*10,
			AffectedObjects: affected,
			Remediation:     ind.Remediation,
			References:      ind.References,
			MITRE:           ind.MITRE,
		}}
	}
	return nil
}

func checkEnterpriseAdmins(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	for _, group := range snapshot.Groups {
		if !isEnterpriseAdminsGroup(group) {
			continue
		}
		// Enterprise Admins should only contain the forest root domain Administrator
		var affected []types.AffectedObject
		for _, memberDN := range group.Members {
			member := findUserByDN(snapshot, memberDN)
			if member != nil && isRID500(member.ObjectSID) {
				continue // This is fine - root domain admin is normally here
			}
			affected = append(affected, types.AffectedObject{
				DN:   memberDN,
				Type: "Principal",
				Name: extractCN(memberDN),
				Detail: "Non-standard member of Enterprise Admins",
			})
		}
		if len(affected) == 0 {
			return nil
		}
		ind := findIndicator("P004")
		return []types.Finding{{
			ScanID:          scanID,
			IndicatorID:     "P004",
			Name:            ind.Name,
			Description:     fmt.Sprintf("Enterprise Admins group has %d non-standard member(s). This group grants forest-wide admin rights.", len(affected)),
			Severity:        types.SeverityHigh,
			Category:        types.CategoryPrivileged,
			RiskScore:       50 + len(affected)*10,
			AffectedObjects: affected,
			Remediation:     ind.Remediation,
			References:      ind.References,
			MITRE:           ind.MITRE,
		}}
	}
	return nil
}

func checkAdminSDHolderDeviations(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject

	for _, acl := range snapshot.ACLs {
		if !strings.Contains(strings.ToUpper(acl.ObjectDN), "CN=ADMINSDHOLDER") {
			continue
		}
		for _, entry := range acl.Entries {
			if entry.IsDangerous {
				affected = append(affected, types.AffectedObject{
					Type:   "ACE",
					Name:   entry.Trustee,
					Detail: fmt.Sprintf("Right: %s | Reason: %s", entry.Rights, entry.DangerReason),
				})
			}
		}
		break
	}

	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("P005")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "P005",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d unexpected ACE(s) on AdminSDHolder. These will propagate to all protected accounts within 60 minutes.", len(affected)),
		Severity:        types.SeverityHigh,
		Category:        types.CategoryPrivileged,
		RiskScore:       50 + len(affected)*10,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

func checkGenericAllOnDomain(snapshot *types.InventorySnapshot, scanID string) []types.Finding {
	var affected []types.AffectedObject

	legitimatePrincipals := map[string]bool{
		"Administrators":   true,
		"Domain Admins":    true,
		"Enterprise Admins": true,
		"SYSTEM":           true,
	}

	for _, acl := range snapshot.ACLs {
		if !isDomainRootDN(acl.ObjectDN, snapshot.Domains) {
			continue
		}
		for _, entry := range acl.Entries {
			if entry.AccessType != "Allow" {
				continue
			}
			if !strings.Contains(strings.ToLower(entry.Rights), "genericall") &&
				!strings.Contains(strings.ToLower(entry.Rights), "full control") {
				continue
			}
			isLegitimate := false
			for legit := range legitimatePrincipals {
				if strings.Contains(entry.Trustee, legit) {
					isLegitimate = true
					break
				}
			}
			if !isLegitimate {
				affected = append(affected, types.AffectedObject{
					Type:   "ACE",
					Name:   entry.Trustee,
					Detail: fmt.Sprintf("Has GenericAll/FullControl on domain root: %s", entry.Rights),
				})
			}
		}
	}

	if len(affected) == 0 {
		return nil
	}
	ind := findIndicator("P006")
	return []types.Finding{{
		ScanID:          scanID,
		IndicatorID:     "P006",
		Name:            ind.Name,
		Description:     fmt.Sprintf("%d account(s) have GenericAll/FullControl on the domain root, enabling complete domain takeover.", len(affected)),
		Severity:        types.SeverityCritical,
		Category:        types.CategoryPrivileged,
		RiskScore:       100,
		AffectedObjects: affected,
		Remediation:     ind.Remediation,
		References:      ind.References,
		MITRE:           ind.MITRE,
	}}
}

// ============================================================
// Helpers
// ============================================================

func isDomainAdminsGroup(g types.ADGroup) bool {
	return strings.Contains(g.Name, "Domain Admins") ||
		strings.HasSuffix(g.ObjectSID, "-512")
}

func isSchemaAdminsGroup(g types.ADGroup) bool {
	return strings.Contains(g.Name, "Schema Admins") ||
		strings.HasSuffix(g.ObjectSID, "-518")
}

func isEnterpriseAdminsGroup(g types.ADGroup) bool {
	return strings.Contains(g.Name, "Enterprise Admins") ||
		strings.HasSuffix(g.ObjectSID, "-519")
}

func findUserByDN(snapshot *types.InventorySnapshot, dn string) *types.ADUser {
	for i, user := range snapshot.Users {
		if strings.EqualFold(user.DistinguishedName, dn) {
			return &snapshot.Users[i]
		}
	}
	return nil
}

func isDomainRootDN(dn string, domains []types.ADDomain) bool {
	for _, domain := range domains {
		if strings.EqualFold(dn, domain.DistinguishedName) {
			return true
		}
	}
	return false
}

func extractCN(dn string) string {
	parts := strings.Split(dn, ",")
	if len(parts) == 0 {
		return dn
	}
	cn := parts[0]
	if strings.HasPrefix(strings.ToUpper(cn), "CN=") {
		return cn[3:]
	}
	return cn
}
