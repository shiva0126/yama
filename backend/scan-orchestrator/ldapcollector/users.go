package ldapcollector

import (
	"strings"
)

// CollectUsers enumerates all user accounts via LDAP and returns a map keyed
// "users" containing a slice of ADUser-compatible maps.
func (c *Collector) CollectUsers() (map[string]interface{}, error) {
	entries, err := c.search(c.baseDN,
		"(&(objectClass=user)(objectCategory=person))",
		[]string{
			"sAMAccountName", "userPrincipalName", "distinguishedName",
			"displayName", "givenName", "sn", "mail", "department", "title",
			"description", "objectSid", "objectGUID",
			"userAccountControl",
			"pwdLastSet", "lastLogon", "lastLogonTimestamp",
			"whenCreated", "whenChanged", "accountExpires",
			"memberOf", "servicePrincipalName",
			"allowedToDelegateTo", "msDS-AllowedToDelegateTo",
			"adminCount", "lockoutTime", "badPwdCount",
			"objectClass", "msDS-KeyCredentialLink",
		},
	)
	if err != nil {
		return nil, err
	}

	users := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		uac := attrInt(e, "userAccountControl")
		memberOf := attrVals(e, "memberOf")
		spns := attrVals(e, "servicePrincipalName")
		privil, privGroups := isPrivileged(memberOf)

		// gMSA / MSA detection via objectClass
		classes := attrVals(e, "objectClass")
		isGMSA := containsStr(classes, "msDS-GroupManagedServiceAccount")
		isMSA := containsStr(classes, "msDS-ManagedServiceAccount")
		isSvcAcct := isGMSA || isMSA || strings.HasSuffix(attrStr(e, "sAMAccountName"), "$")

		// Constrained delegation targets
		delegateTo := append(attrVals(e, "allowedToDelegateTo"), attrVals(e, "msDS-AllowedToDelegateTo")...)

		user := map[string]interface{}{
			// Identity
			"distinguished_name":   attrStr(e, "distinguishedName"),
			"sam_account_name":     attrStr(e, "sAMAccountName"),
			"user_principal_name":  attrStr(e, "userPrincipalName"),
			"display_name":         attrStr(e, "displayName"),
			"given_name":           attrStr(e, "givenName"),
			"surname":              attrStr(e, "sn"),
			"email_address":        attrStr(e, "mail"),
			"department":           attrStr(e, "department"),
			"title":                attrStr(e, "title"),
			"description":          attrStr(e, "description"),
			"domain":               c.domain,
			"object_sid":           attrSID(e, "objectSid"),
			"object_guid":          attrGUID(e, "objectGUID"),
			"user_account_control": uac,

			// Account flags
			"enabled":                      uac&UACDisabled == 0,
			"locked":                        attrInt64(e, "lockoutTime") > 0,
			"password_never_expires":        uac&UACDontExpirePasswd != 0,
			"password_not_required":         uac&UACPasswdNotReqd != 0,
			"password_expired":              uac&UACPasswordExpired != 0,
			"reversible_encryption":         uac&UACReversibleEncryption != 0,
			"smartcard_required":            uac&UACSmartcardRequired != 0,
			"trusted_for_delegation":        uac&UACTrustedForDelegation != 0,
			"trusted_to_auth_for_delegation": uac&UACTrustedToAuth != 0,
			"dont_require_preauth":          uac&UACDontRequirePreauth != 0,
			"use_des_key_only":              uac&UACUseDesKeyOnly != 0,
			"admin_count":                   attrInt(e, "adminCount"),

			// Timestamps
			"created":               winTimeStr(e, "whenCreated"),
			"modified":              winTimeStr(e, "whenChanged"),
			"last_logon":            winTime(attrInt64(e, "lastLogon")),
			"last_logon_timestamp":  winTime(attrInt64(e, "lastLogonTimestamp")),
			"pwd_last_set":          winTime(attrInt64(e, "pwdLastSet")),
			"account_expires":       winTime(attrInt64(e, "accountExpires")),

			// Memberships & SPNs
			"member_of":              memberOf,
			"service_principal_names": spns,
			"allowed_to_delegate_to": delegateTo,

			// Privilege
			"is_privileged":          privil,
			"privileged_groups":      privGroups,
			"is_service_account":     isSvcAcct,
			"is_msa":                 isMSA,
			"is_gmsa":                isGMSA,
			"has_shadow_credentials": len(attrVals(e, "msDS-KeyCredentialLink")) > 0,
		}
		users = append(users, user)
	}

	return map[string]interface{}{"users": users}, nil
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
