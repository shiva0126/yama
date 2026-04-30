package ldapcollector

import "fmt"

// CollectFGPP enumerates Fine-Grained Password Policies (PSOs).
func (c *Collector) CollectFGPP() (map[string]interface{}, error) {
	pscBase := fmt.Sprintf("CN=Password Settings Container,CN=System,%s", c.baseDN)

	entries, err := c.search(pscBase,
		"(objectClass=msDS-PasswordSettings)",
		[]string{
			"name", "distinguishedName",
			"msDS-PasswordSettingsPrecedence",
			"msDS-MinimumPasswordLength",
			"msDS-PasswordHistoryLength",
			"msDS-MaximumPasswordAge",
			"msDS-MinimumPasswordAge",
			"msDS-PasswordComplexityEnabled",
			"msDS-PasswordReversibleEncryptionEnabled",
			"msDS-LockoutThreshold",
			"msDS-LockoutDuration",
			"msDS-LockoutObservationWindow",
			"msDS-PSOAppliesTo",
		},
	)
	if err != nil {
		// PSC might not exist in older domains
		return map[string]interface{}{"fgpps": []interface{}{}}, nil
	}

	fgpps := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		appliesto := attrVals(e, "msDS-PSOAppliesTo")

		fgpp := map[string]interface{}{
			"name":               attrStr(e, "name"),
			"distinguished_name": attrStr(e, "distinguishedName"),
			"precedence":         attrInt(e, "msDS-PasswordSettingsPrecedence"),
			"applies_to":         appliesto,
			"password_policy": map[string]interface{}{
				"min_password_length":    attrInt(e, "msDS-MinimumPasswordLength"),
				"password_history_count": attrInt(e, "msDS-PasswordHistoryLength"),
				"max_password_age":       attrInt64(e, "msDS-MaximumPasswordAge"),
				"min_password_age":       attrInt64(e, "msDS-MinimumPasswordAge"),
				"complexity_enabled":     attrStr(e, "msDS-PasswordComplexityEnabled") == "TRUE",
				"reversible_encryption":  attrStr(e, "msDS-PasswordReversibleEncryptionEnabled") == "TRUE",
			},
			"account_lockout_policy": map[string]interface{}{
				"lockout_threshold":   attrInt(e, "msDS-LockoutThreshold"),
				"lockout_duration":    attrInt64(e, "msDS-LockoutDuration"),
				"observation_window":  attrInt64(e, "msDS-LockoutObservationWindow"),
			},
		}
		fgpps = append(fgpps, fgpp)
	}

	return map[string]interface{}{"fgpps": fgpps}, nil
}
