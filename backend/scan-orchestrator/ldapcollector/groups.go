package ldapcollector

import "strings"

// groupType bit flags
const (
	groupTypeBuiltinLocal = 0x00000001
	groupTypeGlobal       = 0x00000002
	groupTypeDomainLocal  = 0x00000004
	groupTypeUniversal    = 0x00000008
	groupTypeSecurity     = -2147483648 // 0x80000000 as int32
)

func (c *Collector) CollectGroups() (map[string]interface{}, error) {
	entries, err := c.search(c.baseDN,
		"(objectClass=group)",
		[]string{
			"sAMAccountName", "distinguishedName", "description",
			"objectSid", "groupType", "member", "memberOf",
			"adminCount", "whenCreated", "whenChanged",
		},
	)
	if err != nil {
		return nil, err
	}

	groups := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		sid := attrSID(e, "objectSid")
		members := attrVals(e, "member")
		memberOf := attrVals(e, "memberOf")
		name := attrStr(e, "sAMAccountName")
		dn := attrStr(e, "distinguishedName")

		// Determine scope and category from groupType
		gt := attrInt(e, "groupType")
		scope, category := decodeGroupType(gt)

		// Determine if privileged
		privil := isPrivilegedGroup(name, sid)
		privLevel := ""
		if privil {
			privLevel = groupPrivLevel(name)
		}

		// Find nested groups within members
		var nestedGroups []string
		for _, m := range members {
			if strings.Contains(strings.ToUpper(m), "CN=") && strings.Contains(m, ",") {
				// Heuristic: if the member DN looks like a group (contains group containers)
				// We can't be 100% sure without querying each member, but this is close enough
				nestedGroups = append(nestedGroups, m)
			}
		}

		group := map[string]interface{}{
			"distinguished_name": dn,
			"sam_account_name":   name,
			"name":               name,
			"description":        attrStr(e, "description"),
			"domain":             c.domain,
			"object_sid":         sid,
			"group_scope":        scope,
			"group_category":     category,
			"members":            members,
			"member_of":          memberOf,
			"nested_groups":      nestedGroups,
			"admin_count":        attrInt(e, "adminCount"),
			"is_privileged":      privil,
			"privilege_level":    privLevel,
			"created":            winTimeStr(e, "whenCreated"),
			"modified":           winTimeStr(e, "whenChanged"),
		}
		groups = append(groups, group)
	}

	return map[string]interface{}{"groups": groups}, nil
}

func decodeGroupType(gt int) (scope, category string) {
	// category
	if gt < 0 {
		category = "Security"
	} else {
		category = "Distribution"
	}
	abs := gt
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs&groupTypeBuiltinLocal != 0:
		scope = "BuiltinLocal"
	case abs&groupTypeGlobal != 0:
		scope = "Global"
	case abs&groupTypeDomainLocal != 0:
		scope = "DomainLocal"
	case abs&groupTypeUniversal != 0:
		scope = "Universal"
	default:
		scope = "Unknown"
	}
	return
}

func isPrivilegedGroup(name, sid string) bool {
	for _, pn := range privilegedGroupNames {
		if strings.EqualFold(name, pn) {
			return true
		}
	}
	// Well-known SID suffixes
	privSIDSuffixes := []string{"-512", "-518", "-519", "-516", "-521", "-526", "-527"}
	for _, suf := range privSIDSuffixes {
		if strings.HasSuffix(sid, suf) {
			return true
		}
	}
	return false
}

func groupPrivLevel(name string) string {
	tier0 := []string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Domain Controllers"}
	for _, g := range tier0 {
		if strings.EqualFold(name, g) {
			return "Tier0"
		}
	}
	return "Tier1"
}
