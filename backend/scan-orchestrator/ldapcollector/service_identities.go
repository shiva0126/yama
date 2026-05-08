package ldapcollector

import (
	"strings"
)

// CollectServiceIdentities enumerates AD identities tied to service SPNs.
func (c *Collector) CollectServiceIdentities() (map[string]interface{}, error) {
	entries, err := c.search(c.baseDN,
		"(&(objectClass=user)(servicePrincipalName=*))",
		[]string{
			"sAMAccountName", "distinguishedName", "servicePrincipalName",
			"userAccountControl", "adminCount", "memberOf", "lastLogonTimestamp",
		},
	)
	if err != nil {
		return nil, err
	}

	identities := make([]interface{}, 0, len(entries))
	kerberoastable := 0
	privileged := 0
	for _, e := range entries {
		memberOf := attrVals(e, "memberOf")
		isPriv, privGroups := isPrivileged(memberOf)
		if isPriv {
			privileged++
		}

		spns := attrVals(e, "servicePrincipalName")
		isEnabled := attrInt(e, "userAccountControl")&UACDisabled == 0
		if isEnabled {
			kerberoastable++
		}

		identities = append(identities, map[string]interface{}{
			"sam_account_name":      attrStr(e, "sAMAccountName"),
			"distinguished_name":    attrStr(e, "distinguishedName"),
			"service_principal_names": spns,
			"spn_count":             len(spns),
			"enabled":               isEnabled,
			"is_privileged":         isPriv,
			"privileged_groups":     privGroups,
			"last_logon_timestamp":  winTime(attrInt64(e, "lastLogonTimestamp")),
		})
	}

	highRiskSPN := make([]interface{}, 0)
	for _, item := range identities {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		spns, _ := m["service_principal_names"].([]string)
		if len(spns) == 0 {
			continue
		}
		for _, spn := range spns {
			spnLower := strings.ToLower(spn)
			if strings.Contains(spnLower, "mssqlsvc/") || strings.Contains(spnLower, "http/") || strings.Contains(spnLower, "cifs/") {
				highRiskSPN = append(highRiskSPN, map[string]interface{}{
					"sam_account_name": m["sam_account_name"],
					"spn":              spn,
				})
			}
		}
	}

	return map[string]interface{}{
		"service_identities": identities,
		"summary": map[string]interface{}{
			"total_service_identities": len(identities),
			"kerberoastable_accounts":  kerberoastable,
			"privileged_service_accounts": privileged,
			"high_risk_spn_bindings":   len(highRiskSPN),
		},
		"high_risk_spn_bindings": highRiskSPN,
	}, nil
}
