package ldapcollector

// CollectSites enumerates AD Sites and Services — sites, subnets, site links, and
// which DCs belong to which site. This powers the topology visualization.
func (c *Collector) CollectSites() (map[string]interface{}, error) {
	sitesBase := "CN=Sites," + c.configDN

	// 1. Sites
	siteEntries, err := c.search(sitesBase,
		"(objectClass=site)",
		[]string{"cn", "distinguishedName", "description", "siteObjectBL"},
	)
	if err != nil {
		return map[string]interface{}{"sites": []interface{}{}, "site_links": []interface{}{}}, nil
	}

	// Build site → DCs map from siteObjectBL (back-link on server objects)
	// We'll also query server objects directly
	serverEntries, _ := c.search(sitesBase,
		"(objectClass=server)",
		[]string{"cn", "distinguishedName", "serverReference"},
	)

	// Map: site name → []DC names
	siteDCs := map[string][]interface{}{}
	for _, srv := range serverEntries {
		dn := srv.GetAttributeValue("distinguishedName")
		siteName := extractSiteFromServerDN(dn)
		if siteName != "" {
			dcName := attrStr(srv, "cn")
			siteDCs[siteName] = append(siteDCs[siteName], dcName)
		}
	}

	// 2. Subnets
	subnetEntries, _ := c.search("CN=Subnets,"+sitesBase,
		"(objectClass=subnet)",
		[]string{"cn", "distinguishedName", "description", "siteObject"},
	)

	// Map: site name → []subnet CIDR
	siteSubnets := map[string][]interface{}{}
	for _, sub := range subnetEntries {
		cidr := attrStr(sub, "cn")
		siteObj := attrStr(sub, "siteObject")
		if siteObj != "" {
			siteName := extractCN(siteObj)
			siteSubnets[siteName] = append(siteSubnets[siteName], cidr)
		}
	}

	var sites []interface{}
	for _, e := range siteEntries {
		siteName := attrStr(e, "cn")
		sites = append(sites, map[string]interface{}{
			"name":        siteName,
			"description": attrStr(e, "description"),
			"subnets":     orEmpty(siteSubnets[siteName]),
			"dcs":         orEmpty(siteDCs[siteName]),
		})
	}

	// 3. Site Links
	sitelinkEntries, _ := c.search("CN=IP,CN=Inter-Site Transports,"+sitesBase,
		"(objectClass=siteLink)",
		[]string{"cn", "siteList", "cost", "replInterval"},
	)

	var siteLinks []interface{}
	for _, e := range sitelinkEntries {
		siteList := attrVals(e, "siteList")
		siteNames := make([]string, 0, len(siteList))
		for _, sl := range siteList {
			siteNames = append(siteNames, extractCN(sl))
		}
		siteLinks = append(siteLinks, map[string]interface{}{
			"name":                        attrStr(e, "cn"),
			"sites":                       siteNames,
			"cost":                        attrInt(e, "cost"),
			"replication_interval_minutes": attrInt(e, "replInterval"),
		})
	}

	// 4. Also collect domain-level attributes: MachineAccountQuota and Recycle Bin
	machineQuota := 0
	recycleBin := false

	domainRoot, _ := c.searchBase(c.baseDN, "(objectClass=domain)", []string{"ms-DS-MachineAccountQuota"})
	if domainRoot != nil {
		machineQuota = attrInt(domainRoot, "ms-DS-MachineAccountQuota")
	}

	// Recycle Bin: check for the optional feature in the configuration partition
	rbEntries, _ := c.search(
		"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,"+c.configDN,
		"(&(objectClass=msDS-OptionalFeature)(cn=Recycle Bin Feature))",
		[]string{"msDS-EnabledFeatureBL"},
	)
	recycleBin = len(rbEntries) > 0 && len(rbEntries[0].GetAttributeValues("msDS-EnabledFeatureBL")) > 0

	return map[string]interface{}{
		"sites":                 orEmpty(sites),
		"site_links":            orEmpty(siteLinks),
		"machine_account_quota": machineQuota,
		"recycle_bin_enabled":   recycleBin,
	}, nil
}

// extractSiteFromServerDN extracts the site CN from a server object DN like
// CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,...
func extractSiteFromServerDN(dn string) string {
	// Find "CN=Servers," then the next component is "CN=<site>"
	idx := indexOf(dn, "CN=Servers,")
	if idx < 0 {
		return ""
	}
	rest := dn[idx+len("CN=Servers,"):]
	return extractCN(rest)
}

// extractCN returns the value of the first CN= component in a DN.
func extractCN(dn string) string {
	if dn == "" {
		return ""
	}
	for _, part := range splitDN(dn) {
		if len(part) > 3 && part[:3] == "CN=" {
			return part[3:]
		}
	}
	return ""
}

func splitDN(dn string) []string {
	var parts []string
	cur := ""
	for i := 0; i < len(dn); i++ {
		if dn[i] == ',' && (i == 0 || dn[i-1] != '\\') {
			parts = append(parts, cur)
			cur = ""
		} else {
			cur += string(dn[i])
		}
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func orEmpty(s []interface{}) []interface{} {
	if s == nil {
		return []interface{}{}
	}
	return s
}
