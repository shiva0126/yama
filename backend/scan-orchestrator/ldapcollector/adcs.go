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
	ctNameFlagSubjectRequireEmail            = 0x00000040
	ctNameFlagEnrolleeSuppliesSubjectAltName = 0x00010000
	ctNameFlagSubjectRequireDNS              = 0x00000008
	ctNameFlagSubjectRequireEmail2           = 0x00000040
)

// msPKI-Private-Key-Flag
const (
	ctKeyFlagRequireAltSignatureAlgorithm = 0x00000004
)

// EKU OIDs for ESC10 / PKINIT
const (
	ekuSmartcardLogon = "1.3.6.1.4.1.311.20.2.2"
	ekuPKINITKDC      = "1.3.6.1.5.2.3.5"
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
			"msPKI-Private-Key-Flag",
			"pKIExtendedKeyUsage",
			"msPKI-Certificate-Application-Policy",
			"msPKI-RA-Application-Policies",
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
		schemaVersion := attrInt(e, "msPKI-Template-Schema-Version")
		ekus := attrVals(e, "pKIExtendedKeyUsage")
		appPolicies := attrVals(e, "msPKI-Certificate-Application-Policy")
		raPolicies := attrVals(e, "msPKI-RA-Application-Policies")

		enrolleeSuppliesSubject := (enrollFlag&ctFlagEnrolleeSuppliesSubject != 0) ||
			(nameFlag&ctNameFlagEnrolleeSuppliesSubjectAltName != 0)
		reqApproval := enrollFlag&ctFlagPendAllRequests != 0
		noSecurityExtension := enrollFlag&ctFlagNoSecurityExtension != 0

		hasClientAuth := false
		hasAnyPurpose := false
		hasCertReqAgent := false
		hasSmartcardLogon := false
		hasPKINITKDC := false
		for _, eku := range ekus {
			switch eku {
			case ekuClientAuth:
				hasClientAuth = true
			case ekuAnyPurpose:
				hasAnyPurpose = true
			case ekuCertRequestAgent:
				hasCertReqAgent = true
			case ekuSmartcardLogon:
				hasSmartcardLogon = true
			case ekuPKINITKDC:
				hasPKINITKDC = true
			}
		}
		// No EKU at all = SubCA / Any Purpose equivalent
		if len(ekus) == 0 {
			hasAnyPurpose = true
		}

		lowPrivEnroll := !reqApproval

		esc1 := enrolleeSuppliesSubject && hasClientAuth && lowPrivEnroll
		esc2 := hasAnyPurpose && lowPrivEnroll
		esc3 := hasCertReqAgent && lowPrivEnroll

		// ESC9: CT_FLAG_NO_SECURITY_EXTENSION + client auth + low-priv enrollment
		// The szOID_NTDS_CA_SECURITY_EXT extension is omitted, enabling UPN spoofing.
		esc9 := noSecurityExtension && hasClientAuth && lowPrivEnroll

		// ESC10: Template enables PKINIT or Smartcard Logon + low-priv enrollment.
		// Combined with weak certificate mapping enforcement (can't check via LDAP),
		// this allows authentication as arbitrary users via certificate spoofing.
		esc10 := (hasSmartcardLogon || hasPKINITKDC) && hasClientAuth && lowPrivEnroll

		// ESC13: Issuance policy OID linked to a universal group (OID group link).
		// Detectable when RA-Application-Policies reference issuance policy OIDs
		// that may be mapped to group memberships via OID directory objects.
		hasIssuancePolicyRA := false
		for _, p := range raPolicies {
			// Issuance policy OIDs start with 1.3.6.1.4.1.311.21.8 (enterprise-specific)
			// or match the format used for OID group links
			if strings.HasPrefix(p, "1.3.6.1.4.1.311.21.8") {
				hasIssuancePolicyRA = true
				break
			}
		}
		for _, p := range appPolicies {
			if strings.HasPrefix(p, "1.3.6.1.4.1.311.21.8") {
				hasIssuancePolicyRA = true
				break
			}
		}
		esc13 := hasIssuancePolicyRA && hasClientAuth && lowPrivEnroll

		// ESC15: Schema version 1 template with enrollee-supplied subject (msPKI-Template-Schema-Version=1).
		// Schema v1 templates do not enforce the application policies extension, allowing
		// SAN spoofing even without the enrolleeSuppliesSubject flag being explicitly set.
		esc15 := schemaVersion == 1 && hasClientAuth && lowPrivEnroll

		t := map[string]interface{}{
			"name":                        attrStr(e, "cn"),
			"display_name":                displayName,
			"distinguished_name":          dn,
			"extended_key_usage":          ekus,
			"schema_version":              schemaVersion,
			"enrollee_supplies_subject":   enrolleeSuppliesSubject,
			"requires_manager_approval":   reqApproval,
			"no_security_extension":       noSecurityExtension,
			"has_client_auth":             hasClientAuth,
			"has_any_purpose":             hasAnyPurpose,
			"has_cert_request_agent":      hasCertReqAgent,
			"has_smartcard_logon":         hasSmartcardLogon,
			"has_pkinit_kdc":              hasPKINITKDC,
			"low_priv_enrollment":         lowPrivEnroll,
			"vulnerable_esc1":             esc1,
			"vulnerable_esc2":             esc2,
			"vulnerable_esc3":             esc3,
			"vulnerable_esc4":             false, // requires ACL parse — set by acls collector
			"vulnerable_esc9":             esc9,
			"vulnerable_esc10":            esc10,
			"vulnerable_esc13":            esc13,
			"vulnerable_esc15":            esc15,
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
			"msPKI-Enrollment-Servers", // RPC enrollment endpoint info
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
		// We can't read that via LDAP directly; flag it if the flags attribute bit is set.
		userSpecifiedSAN := flags&0x00040000 != 0

		// Check for web enrollment endpoint indicator in dNSHostName
		webEnroll := dns != "" && !strings.Contains(strings.ToLower(dns), "none")

		// ESC11: NTLM relay to ICPR (RPC) endpoint. Detectable when the CA exposes
		// an RPC enrollment endpoint (msPKI-Enrollment-Servers with priority 0).
		// Mapped to request_encryption_disabled to match ADCertificateAuthority struct.
		enrollServers := attrVals(e, "msPKI-Enrollment-Servers")
		requestEncryptionDisabled := false
		for _, srv := range enrollServers {
			// Format: "Priority\nAuthType\nEndpoint" — priority 0 = unauthenticated/unencrypted RPC
			if strings.HasPrefix(srv, "0\n") {
				requestEncryptionDisabled = true
				break
			}
		}

		ca := map[string]interface{}{
			"name":                        name,
			"distinguished_name":          dn,
			"dns_host_name":               dns,
			"flags":                       flags,
			"user_specified_san":          userSpecifiedSAN,
			"manage_ca_low_priv":          false, // requires ACL parse
			"web_enrollment_enabled":      webEnroll,
			"request_encryption_disabled": requestEncryptionDisabled,
			"shell_access_enabled":        false, // requires local agent check
			"templates":                   templates,
		}
		cas = append(cas, ca)
	}
	return cas, nil
}
