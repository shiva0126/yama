package ldapcollector

func (c *Collector) CollectComputers() (map[string]interface{}, error) {
	entries, err := c.search(c.baseDN,
		"(objectClass=computer)",
		[]string{
			"sAMAccountName", "dNSHostName", "distinguishedName",
			"objectSid", "operatingSystem", "operatingSystemVersion",
			"userAccountControl", "servicePrincipalName",
			"allowedToDelegateTo", "msDS-AllowedToDelegateTo",
			"memberOf", "whenCreated", "whenChanged",
			"lastLogon", "lastLogonTimestamp", "pwdLastSet",
			"ms-Mcs-AdmPwdExpirationTime",   // Legacy LAPS
			"msLAPS-PasswordExpirationTime", // Windows LAPS
		},
	)
	if err != nil {
		return nil, err
	}

	computers := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		uacVal := attrInt(e, "userAccountControl")
		isDC := uacVal&UACServerTrustAccount != 0
		isRODC := uacVal&0x04000000 != 0 // PARTIAL_SECRETS_ACCOUNT

		delegateTo := append(
			attrVals(e, "allowedToDelegateTo"),
			attrVals(e, "msDS-AllowedToDelegateTo")...,
		)

		// LAPS: either attribute being non-empty means LAPS is deployed
		lapsExpiry := attrStr(e, "ms-Mcs-AdmPwdExpirationTime")
		if lapsExpiry == "" {
			lapsExpiry = attrStr(e, "msLAPS-PasswordExpirationTime")
		}
		lapsEnabled := lapsExpiry != ""

		comp := map[string]interface{}{
			"distinguished_name":          attrStr(e, "distinguishedName"),
			"sam_account_name":            attrStr(e, "sAMAccountName"),
			"name":                        stripDollar(attrStr(e, "sAMAccountName")),
			"dns_host_name":               attrStr(e, "dNSHostName"),
			"domain":                      c.domain,
			"object_sid":                  attrSID(e, "objectSid"),
			"operating_system":            attrStr(e, "operatingSystem"),
			"operating_system_version":    attrStr(e, "operatingSystemVersion"),
			"enabled":                     uacVal&UACDisabled == 0,
			"is_domain_controller":        isDC,
			"is_read_only_dc":             isRODC,
			"trusted_for_delegation":      uacVal&UACTrustedForDelegation != 0,
			"trusted_to_auth_for_delegation": uacVal&UACTrustedToAuth != 0,
			"allowed_to_delegate_to":      delegateTo,
			"laps_enabled":                lapsEnabled,
			"member_of":                   attrVals(e, "memberOf"),
			"service_principal_names":     attrVals(e, "servicePrincipalName"),
			"user_account_control":        uacVal,
			"created":                     winTimeStr(e, "whenCreated"),
			"modified":                    winTimeStr(e, "whenChanged"),
			"last_logon":                  winTime(attrInt64(e, "lastLogon")),
			"last_logon_timestamp":        winTime(attrInt64(e, "lastLogonTimestamp")),
			"pwd_last_set":                winTime(attrInt64(e, "pwdLastSet")),
		}
		computers = append(computers, comp)
	}

	return map[string]interface{}{"computers": computers}, nil
}

func stripDollar(s string) string {
	if len(s) > 0 && s[len(s)-1] == '$' {
		return s[:len(s)-1]
	}
	return s
}
