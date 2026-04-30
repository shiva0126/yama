package ldapcollector

import (
	"fmt"
	"strings"
)

// CollectGPOs enumerates Group Policy Objects from the Policies container.
func (c *Collector) CollectGPOs() (map[string]interface{}, error) {
	policiesBase := fmt.Sprintf("CN=Policies,CN=System,%s", c.baseDN)

	entries, err := c.search(policiesBase,
		"(objectClass=groupPolicyContainer)",
		[]string{
			"displayName", "distinguishedName", "gPCFileSysPath",
			"flags", "versionNumber", "whenCreated", "whenChanged",
			"objectGUID",
		},
	)
	if err != nil {
		// Try base search
		entries, err = c.search(c.baseDN,
			"(objectClass=groupPolicyContainer)",
			[]string{
				"displayName", "distinguishedName", "gPCFileSysPath",
				"flags", "versionNumber", "whenCreated", "whenChanged",
				"objectGUID",
			},
		)
		if err != nil {
			return nil, err
		}
	}

	// Collect all OU gPLink attributes to determine which GPOs are linked
	linkedGUIDs := buildLinkedGUIDSet(c)

	gpos := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		guid := attrGUID(e, "objectGUID")
		dn := attrStr(e, "distinguishedName")
		name := attrStr(e, "displayName")

		// flags: 0=all enabled, 1=user disabled, 2=computer disabled, 3=all disabled
		flags := attrInt(e, "flags")
		status := gpoStatus(flags)

		isLinked := linkedGUIDs[strings.ToLower(guid)]

		// Version: high word = computer version, low word = user version
		version := attrInt(e, "versionNumber")
		computerVer := (version >> 16) & 0xFFFF
		userVer := version & 0xFFFF

		gpo := map[string]interface{}{
			"id":               guid,
			"name":             name,
			"display_name":     name,
			"distinguished_name": dn,
			"domain":           c.domain,
			"status":           status,
			"is_linked":        isLinked,
			"computer_version": computerVer,
			"user_version":     userVer,
			"created":          winTimeStr(e, "whenCreated"),
			"modified":         winTimeStr(e, "whenChanged"),
			"gpc_file_sys_path": attrStr(e, "gPCFileSysPath"),
		}
		gpos = append(gpos, gpo)
	}

	return map[string]interface{}{"gpos": gpos}, nil
}

func gpoStatus(flags int) string {
	switch flags {
	case 0:
		return "AllSettingsEnabled"
	case 1:
		return "UserSettingsDisabled"
	case 2:
		return "ComputerSettingsDisabled"
	case 3:
		return "AllSettingsDisabled"
	default:
		return "AllSettingsEnabled"
	}
}

// buildLinkedGUIDSet reads gPLink from all OUs and the domain root to find which GPO GUIDs are linked.
func buildLinkedGUIDSet(c *Collector) map[string]bool {
	linked := map[string]bool{}

	// Search all OUs for gPLink
	entries, err := c.search(c.baseDN,
		"(|(objectClass=organizationalUnit)(objectClass=domain))",
		[]string{"gPLink"},
	)
	if err != nil {
		return linked
	}

	for _, e := range entries {
		gplink := attrStr(e, "gPLink")
		// gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;flags]...
		for _, part := range strings.Split(gplink, "][") {
			part = strings.Trim(part, "[]")
			if idx := strings.Index(strings.ToUpper(part), "{"); idx >= 0 {
				end := strings.Index(part[idx:], "}")
				if end > 0 {
					guid := strings.ToLower(part[idx+1 : idx+end])
					linked[guid] = true
				}
			}
		}
	}
	return linked
}
