package ldapcollector

import "strings"

// CollectOUs enumerates Organizational Units.
func (c *Collector) CollectOUs() (map[string]interface{}, error) {
	entries, err := c.search(c.baseDN,
		"(objectClass=organizationalUnit)",
		[]string{
			"name", "distinguishedName", "description",
			"gPLink", "whenCreated", "whenChanged",
		},
	)
	if err != nil {
		return nil, err
	}

	ous := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		dn := attrStr(e, "distinguishedName")
		gplink := attrStr(e, "gPLink")

		// Extract linked GPO GUIDs from gPLink
		var linkedGPOs []string
		for _, part := range strings.Split(gplink, "][") {
			part = strings.Trim(part, "[]")
			if idx := strings.Index(strings.ToUpper(part), "{"); idx >= 0 {
				end := strings.Index(part[idx:], "}")
				if end > 0 {
					linkedGPOs = append(linkedGPOs, part[idx:idx+end+1])
				}
			}
		}

		// Determine parent OU from DN
		parts := strings.SplitN(dn, ",", 2)
		parentDN := ""
		if len(parts) > 1 {
			parentDN = parts[1]
		}

		ou := map[string]interface{}{
			"distinguished_name": dn,
			"name":               attrStr(e, "name"),
			"domain":             c.domain,
			"description":        attrStr(e, "description"),
			"linked_gpos":        linkedGPOs,
			"parent_dn":          parentDN,
			"created":            winTimeStr(e, "whenCreated"),
			"modified":           winTimeStr(e, "whenChanged"),
		}
		ous = append(ous, ou)
	}

	return map[string]interface{}{"ous": ous}, nil
}
