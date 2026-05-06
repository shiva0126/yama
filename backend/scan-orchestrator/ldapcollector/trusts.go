package ldapcollector

import (
	"fmt"
	"strings"
)

// trustType values
var trustTypeNames = map[int]string{
	1: "Windows NT",
	2: "Active Directory",
	3: "Kerberos",
	4: "DCE",
}

// trustDirection values
var trustDirectionNames = map[int]string{
	0: "None",
	1: "Inbound",
	2: "Outbound",
	3: "Bidirectional",
}

// trustAttribute bits
const (
	TRUST_ATTRIBUTE_NON_TRANSITIVE         = 0x0001
	TRUST_ATTRIBUTE_UPLEVEL_ONLY           = 0x0002
	TRUST_ATTRIBUTE_QUARANTINED_DOMAIN     = 0x0004 // SID filtering enabled
	TRUST_ATTRIBUTE_FOREST_TRANSITIVE      = 0x0008
	TRUST_ATTRIBUTE_CROSS_ORGANIZATION     = 0x0010 // Selective auth
	TRUST_ATTRIBUTE_WITHIN_FOREST          = 0x0020
	TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL      = 0x0040
	TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION    = 0x0080
)

// CollectTrusts enumerates domain trusts from CN=System.
func (c *Collector) CollectTrusts() (map[string]interface{}, error) {
	systemBase := fmt.Sprintf("CN=System,%s", c.baseDN)

	entries, err := c.search(systemBase,
		"(objectClass=trustedDomain)",
		[]string{
			"name", "distinguishedName", "trustPartner",
			"trustType", "trustDirection", "trustAttributes",
			"whenCreated", "whenChanged",
		},
	)
	if err != nil {
		// Fall back to full tree search
		entries, err = c.search(c.baseDN,
			"(objectClass=trustedDomain)",
			[]string{
				"name", "distinguishedName", "trustPartner",
				"trustType", "trustDirection", "trustAttributes",
				"whenCreated", "whenChanged",
			},
		)
		if err != nil {
			return nil, err
		}
	}

	trusts := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		attrs := attrInt(e, "trustAttributes")
		direction := attrInt(e, "trustDirection")
		trustType := attrInt(e, "trustType")

		typeName := trustTypeNames[trustType]
		if typeName == "" {
			typeName = "Unknown"
		}
		dirName := trustDirectionNames[direction]
		if dirName == "" {
			dirName = "Unknown"
		}

		sidFiltering := attrs&TRUST_ATTRIBUTE_QUARANTINED_DOMAIN != 0
		selectiveAuth := attrs&TRUST_ATTRIBUTE_CROSS_ORGANIZATION != 0
		isTransitive := attrs&TRUST_ATTRIBUTE_NON_TRANSITIVE == 0

		// Determine trust type string for the frontend
		trustTypeStr := "External"
		if attrs&TRUST_ATTRIBUTE_FOREST_TRANSITIVE != 0 {
			trustTypeStr = "Forest"
		} else if attrs&TRUST_ATTRIBUTE_WITHIN_FOREST != 0 {
			trustTypeStr = "ParentChild"
		}

		trust := map[string]interface{}{
			"source_domain":    c.domain,
			"target_domain":    attrStr(e, "trustPartner"),
			"trust_type":       trustTypeStr,
			"trust_direction":  dirName,
			"trust_attributes": attrs,
			"is_transitive":    isTransitive,
			"sid_filtering":    sidFiltering,
			"selective_auth":   selectiveAuth,
			"trust_type_raw":   typeName,
			"created":          winTimeStr(e, "whenCreated"),
			"modified":         winTimeStr(e, "whenChanged"),
		}
		trusts = append(trusts, trust)
	}

	return map[string]interface{}{
		"trusts": trusts,
		"domain": strings.ToLower(c.domain),
	}, nil
}
