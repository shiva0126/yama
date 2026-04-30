package ldapcollector

import (
	"strings"
)

// EKU OIDs relevant for ADCS vulnerability detection
const (
	ekuClientAuth       = "1.3.6.1.5.5.7.3.2"
	ekuAnyPurpose       = "2.5.29.37.0"
	ekuCertRequestAgent = "1.3.6.1.4.1.311.20.2.1"
	ekuSubCA            = "" // no EKU = SubCA capable
)

// CT_FLAG values from msPKI-Enrollment-Flag
const (
	ctFlagEnrolleeSuppliesSubject = 0x00000001
	ctFlagPendAllRequests         = 0x00000002 // requires manager approval
	ctFlagNoSecurityExtension     = 0x00080000
)

// msPKI-Certificate-Name-Flag
const (
	ctNameFlagSubjectRequireEmail           = 0x00000040
	ctNameFlagEnrolleeSuppliesSubjectAltName = 0x00010000
)

func (c *Collector) CollectADCS() (map[string]interface{}, error) {
	templates, err := c.collectCertTemplates()
	if err != nil {
		// ADCS may not be deployed — return empty gracefully
		return map[string]interface{}{
			"cert_templates":    []interface{}{},
			"cert_authorities":  []interface{}{},
		}, nil
	}

	cas, err := c.collectCertAuthorities()
	if err != nil {
		cas = []interface{}{}
	}

	return map[string]interface{}{
		"cert_templates":   templates,
		"cert_authorities": cas,
	}, nil
}

func (c *Collector) collectCertTemplates() ([]interface{}, error) {
	base := "CN=Certificate Templates,CN=Public Key Services,CN=Services," + c.configDN
	entries, err := c.search(base,
		"(objectClass=pKICertificateTemplate)",
		[]string{
			"cn", "displayName", "distinguishedName",
			"msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag",
			"msPKI-RA-Signature", "msPKI-Template-Schema-Version",
			"pKIExtendedKeyUsage",
			"nTSecurityDescriptor",
		},
	)
	if err != nil {
		return nil, err
	}

	var templates []interface{}
	for _, e := range entries {
		displayName := attrStr(e, "displayName")
		if displayName == "" {
			displayName = attrStr(e, "cn")
		}
		dn := attrStr(e, "distinguishedName")
		enrollFlag := attrInt(e, "msPKI-Enrollment-Flag")
		nameFlag := attrInt(e, "msPKI-Certificate-Name-Flag")
		ekus := attrVals(e, "pKIExtendedKeyUsage")

		enrolleeSuppliesSubject := (enrollFlag&ctFlagEnrolleeSuppliesSubject != 0) ||
			(nameFlag&ctNameFlagEnrolleeSuppliesSubjectAltName != 0)
		reqApproval := enrollFlag&ctFlagPendAllRequests != 0

		hasClientAuth := false
		hasAnyPurpose := false
		hasCertReqAgent := false
		for _, eku := range ekus {
			switch eku {
			case ekuClientAuth:
				hasClientAuth = true
			case ekuAnyPurpose:
				hasAnyPurpose = true
			case ekuCertRequestAgent:
				hasCertReqAgent = true
			}
		}
		// No EKU at all = SubCA / Any Purpose equivalent
		if len(ekus) == 0 {
			hasAnyPurpose = true
		}

		// ESC1: enrollee supplies SAN + client auth + no approval required
		// We mark lowPrivEnroll as true by default since we can't read ACLs in depth here;
		// the flag is refined by checking enrollment rights if possible.
		lowPrivEnroll := !reqApproval // conservative: assume low-priv unless approval required

		esc1 := enrolleeSuppliesSubject && hasClientAuth && lowPrivEnroll
		esc2 := hasAnyPurpose && lowPrivEnroll
		esc3 := hasCertReqAgent && lowPrivEnroll

		t := map[string]interface{}{
			"name":                       attrStr(e, "cn"),
			"display_name":               displayName,
			"distinguished_name":         dn,
			"extended_key_usage":         ekus,
			"enrollee_supplies_subject":  enrolleeSuppliesSubject,
			"requires_manager_approval":  reqApproval,
			"has_client_auth":            hasClientAuth,
			"has_any_purpose":            hasAnyPurpose,
			"has_cert_request_agent":     hasCertReqAgent,
			"low_priv_enrollment":        lowPrivEnroll,
			"vulnerable_esc1":            esc1,
			"vulnerable_esc2":            esc2,
			"vulnerable_esc3":            esc3,
			"vulnerable_esc4":            false, // requires ACL parse — set by acls collector
		}
		templates = append(templates, t)
	}
	return templates, nil
}

func (c *Collector) collectCertAuthorities() ([]interface{}, error) {
	base := "CN=Enrollment Services,CN=Public Key Services,CN=Services," + c.configDN
	entries, err := c.search(base,
		"(objectClass=pKIEnrollmentService)",
		[]string{
			"cn", "distinguishedName", "dNSHostName",
			"flags", "certificateTemplates",
		},
	)
	if err != nil {
		return nil, err
	}

	var cas []interface{}
	for _, e := range entries {
		name := attrStr(e, "cn")
		dn := attrStr(e, "distinguishedName")
		dns := attrStr(e, "dNSHostName")
		flags := attrInt(e, "flags")
		templates := attrVals(e, "certificateTemplates")

		// EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 in the editFlags registry key.
		// We can't read that via LDAP directly; flag it if the flags attribute bit is set
		// or if it was collected via the topology collector.
		// We check the CA flags field bit 0x00040000 which maps to the editFlags value.
		userSpecifiedSAN := flags&0x00040000 != 0

		// Check for web enrollment endpoint indicator in dNSHostName
		webEnroll := dns != "" && !strings.Contains(strings.ToLower(dns), "none")

		ca := map[string]interface{}{
			"name":                  name,
			"distinguished_name":    dn,
			"dns_host_name":         dns,
			"flags":                 flags,
			"user_specified_san":    userSpecifiedSAN,
			"manage_ca_low_priv":    false, // requires ACL parse
			"web_enrollment_enabled": webEnroll,
			"templates":             templates,
		}
		cas = append(cas, ca)
	}
	return cas, nil
}
