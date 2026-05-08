package ldapcollector

import (
	"strings"
	"time"
)

// CollectADVulnerabilityScan produces a domain-wide vulnerability posture summary.
func (c *Collector) CollectADVulnerabilityScan() (map[string]interface{}, error) {
	vulnerabilities := make([]interface{}, 0)
	totalCritical := 0
	totalHigh := 0
	totalMedium := 0

	// 1) AS-REP roastable users
	asrepEntries, err := c.search(c.baseDN,
		"(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName", "distinguishedName"},
	)
	if err == nil && len(asrepEntries) > 0 {
		totalHigh += len(asrepEntries)
		vulnerabilities = append(vulnerabilities, map[string]interface{}{
			"id":          "asrep-roastable-users",
			"title":       "AS-REP roastable accounts detected",
			"severity":    "high",
			"count":       len(asrepEntries),
			"description": "Accounts with pre-authentication disabled can be targeted for offline password cracking.",
		})
	}

	// 2) Kerberoastable privileged service accounts
	spnEntries, err := c.search(c.baseDN,
		"(&(objectClass=user)(servicePrincipalName=*))",
		[]string{"sAMAccountName", "memberOf"},
	)
	privilegedSPN := 0
	if err == nil {
		for _, entry := range spnEntries {
			isPriv, _ := isPrivileged(attrVals(entry, "memberOf"))
			if isPriv {
				privilegedSPN++
			}
		}
	}
	if privilegedSPN > 0 {
		totalCritical += privilegedSPN
		vulnerabilities = append(vulnerabilities, map[string]interface{}{
			"id":          "privileged-kerberoastable-accounts",
			"title":       "Privileged Kerberoastable service accounts",
			"severity":    "critical",
			"count":       privilegedSPN,
			"description": "Privileged accounts with SPNs increase blast radius if tickets are cracked.",
		})
	}

	// 3) Unconstrained delegation on computers
	computerEntries, err := c.search(c.baseDN,
		"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
		[]string{"sAMAccountName"},
	)
	if err == nil && len(computerEntries) > 0 {
		totalHigh += len(computerEntries)
		vulnerabilities = append(vulnerabilities, map[string]interface{}{
			"id":          "unconstrained-delegation",
			"title":       "Unconstrained delegation hosts",
			"severity":    "high",
			"count":       len(computerEntries),
			"description": "Unconstrained delegation can expose TGTs and accelerate lateral movement.",
		})
	}

	// 4) KRBTGT rotation stale
	kerberosData, kerr := c.CollectKerberos()
	if kerr == nil {
		if k, ok := kerberosData["kerberos"].(map[string]interface{}); ok {
			age := 0
			switch typed := k["krbtgt_password_age_days"].(type) {
			case int:
				age = typed
			case float64:
				age = int(typed)
			}
			if age > 180 {
				totalCritical++
				vulnerabilities = append(vulnerabilities, map[string]interface{}{
					"id":          "stale-krbtgt-password",
					"title":       "KRBTGT password is stale",
					"severity":    "critical",
					"count":       1,
					"description": "KRBTGT password should be rotated regularly to reduce Golden Ticket risk.",
					"metadata": map[string]interface{}{
						"krbtgt_password_age_days": age,
					},
				})
			}
		}
	}

	// 5) Stale privileged users (90+ days)
	userEntries, err := c.search(c.baseDN,
		"(&(objectClass=user)(objectCategory=person)(adminCount=1))",
		[]string{"sAMAccountName", "lastLogonTimestamp"},
	)
	stalePrivileged := 0
	if err == nil {
		cutoff := time.Now().AddDate(0, 0, -90)
		for _, e := range userEntries {
			lastLogon := winTime(attrInt64(e, "lastLogonTimestamp"))
			if lastLogon.IsZero() || lastLogon.Before(cutoff) {
				stalePrivileged++
			}
		}
	}
	if stalePrivileged > 0 {
		totalMedium += stalePrivileged
		vulnerabilities = append(vulnerabilities, map[string]interface{}{
			"id":          "stale-privileged-identities",
			"title":       "Stale privileged identities",
			"severity":    "medium",
			"count":       stalePrivileged,
			"description": "Privileged accounts without recent activity should be reviewed and disabled if unnecessary.",
		})
	}

	// 6) Legacy DES-only accounts from Kerberos posture
	if kerr == nil {
		if k, ok := kerberosData["kerberos"].(map[string]interface{}); ok {
			if desList, ok := k["des_enabled_accounts"].([]interface{}); ok && len(desList) > 0 {
				totalMedium += len(desList)
				vulnerabilities = append(vulnerabilities, map[string]interface{}{
					"id":          "des-encryption-enabled",
					"title":       "DES-enabled Kerberos accounts",
					"severity":    "medium",
					"count":       len(desList),
					"description": "Legacy DES encryption weakens Kerberos security and should be removed.",
				})
			}
		}
	}

	// Domain-wide score heuristic
	score := 100 - (totalCritical * 8) - (totalHigh * 4) - (totalMedium * 2)
	if score < 0 {
		score = 0
	}

	topFindings := make([]interface{}, 0, len(vulnerabilities))
	for _, item := range vulnerabilities {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		title, _ := m["title"].(string)
		severity, _ := m["severity"].(string)
		count, _ := m["count"].(int)
		if count == 0 {
			if f, ok := m["count"].(float64); ok {
				count = int(f)
			}
		}
		topFindings = append(topFindings, map[string]interface{}{
			"title":    title,
			"severity": strings.ToLower(severity),
			"count":    count,
		})
	}

	return map[string]interface{}{
		"vulnerabilities": vulnerabilities,
		"summary": map[string]interface{}{
			"critical":            totalCritical,
			"high":                totalHigh,
			"medium":              totalMedium,
			"estimated_risk_score": score,
		},
		"top_findings": topFindings,
	}, nil
}
