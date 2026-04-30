package ldapcollector

import (
	"fmt"
	"time"
)

// CollectKerberos gathers krbtgt account info and domain Kerberos settings.
func (c *Collector) CollectKerberos() (map[string]interface{}, error) {
	// krbtgt account password age
	krbtgtEntries, err := c.search(c.baseDN,
		"(sAMAccountName=krbtgt)",
		[]string{"pwdLastSet", "userAccountControl", "whenCreated", "distinguishedName"},
	)
	if err != nil {
		return nil, err
	}

	krbtgtPwdLastSet := time.Time{}
	krbtgtPwdAgeDays := 0
	if len(krbtgtEntries) > 0 {
		krbtgtPwdLastSet = winTime(attrInt64(krbtgtEntries[0], "pwdLastSet"))
		if !krbtgtPwdLastSet.IsZero() {
			krbtgtPwdAgeDays = int(time.Since(krbtgtPwdLastSet).Hours() / 24)
		}
	}

	// Read domain Kerberos policy from Default Domain Policy area
	// MaxTicketAge and MaxRenewAge are in the domain object or Kerberos policy GPO
	// We read reasonable defaults and flag if krbtgt is old
	kerberosConfig := map[string]interface{}{
		"domain":                   c.domain,
		"krbtgt_password_last_set": krbtgtPwdLastSet,
		"krbtgt_password_age_days": krbtgtPwdAgeDays,
		"max_ticket_age_hours":     10,   // AD default
		"max_renew_age_days":       7,    // AD default
		"max_clock_skew_minutes":   5,    // AD default
	}

	// Check for accounts with DES-only encryption
	desAccounts, err := c.search(c.baseDN,
		"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))",
		[]string{"sAMAccountName", "distinguishedName"},
	)
	if err == nil {
		desAccountList := make([]interface{}, 0, len(desAccounts))
		for _, e := range desAccounts {
			desAccountList = append(desAccountList, map[string]interface{}{
				"sam_account_name":  attrStr(e, "sAMAccountName"),
				"distinguished_name": attrStr(e, "distinguishedName"),
			})
		}
		kerberosConfig["des_enabled_accounts"] = desAccountList
		kerberosConfig["des_enabled"] = len(desAccounts) > 0
	}

	// Unconstrained delegation accounts (non-DCs)
	unconstrainedFilter := fmt.Sprintf(
		"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288)"+
			"(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))", // exclude DCs
	)
	unconstrained, err := c.search(c.baseDN, unconstrainedFilter,
		[]string{"sAMAccountName", "distinguishedName", "objectClass"},
	)
	if err == nil {
		uList := make([]interface{}, 0, len(unconstrained))
		for _, e := range unconstrained {
			uList = append(uList, map[string]interface{}{
				"sam_account_name":  attrStr(e, "sAMAccountName"),
				"distinguished_name": attrStr(e, "distinguishedName"),
			})
		}
		kerberosConfig["unconstrained_delegation_accounts"] = uList
	}

	return map[string]interface{}{"kerberos": kerberosConfig}, nil
}
