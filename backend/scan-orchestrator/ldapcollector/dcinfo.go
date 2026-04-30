package ldapcollector

// CollectDCInfo enumerates domain controllers using userAccountControl bit 0x2000.
func (c *Collector) CollectDCInfo() (map[string]interface{}, error) {
	// LDAP filter: computers with SERVER_TRUST_ACCOUNT bit set
	entries, err := c.search(c.baseDN,
		"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{
			"name", "dNSHostName", "distinguishedName",
			"operatingSystem", "operatingSystemVersion",
			"userAccountControl", "whenCreated", "whenChanged",
			"servicePrincipalName", "lastLogon",
		},
	)
	if err != nil {
		return nil, err
	}

	dcs := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		uacVal := attrInt(e, "userAccountControl")
		isRODC := uacVal&0x04000000 != 0 // PARTIAL_SECRETS_ACCOUNT = RODC

		// Check if Global Catalog by looking for GC SPN
		isGC := false
		for _, spn := range attrVals(e, "servicePrincipalName") {
			if len(spn) > 3 && spn[:3] == "GC/" {
				isGC = true
				break
			}
		}

		dc := map[string]interface{}{
			"name":             attrStr(e, "name"),
			"host_name":        attrStr(e, "dNSHostName"),
			"domain":           c.domain,
			"operating_system": attrStr(e, "operatingSystem"),
			"os_version":       attrStr(e, "operatingSystemVersion"),
			"is_read_only":     isRODC,
			"is_global_catalog": isGC,
			"last_logon":       winTime(attrInt64(e, "lastLogon")),
		}
		dcs = append(dcs, dc)
	}

	return map[string]interface{}{"domain_controllers": dcs}, nil
}
