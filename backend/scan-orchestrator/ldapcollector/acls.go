package ldapcollector

import (
	"encoding/binary"
	"fmt"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// CollectACLs reads nTSecurityDescriptor from critical AD objects to find dangerous ACEs.
// These checks require read access to security descriptors — granted to domain users by default
// for most objects, except some protected ones that require adminSDHolder context.
func (c *Collector) CollectACLs() (map[string]interface{}, error) {
	acls := make([]interface{}, 0)

	// Critical objects to check
	criticalObjects := []struct {
		dn      string
		objType string
	}{
		{c.baseDN, "Domain"},
		{fmt.Sprintf("CN=AdminSDHolder,CN=System,%s", c.baseDN), "AdminSDHolder"},
	}

	// Add privileged groups
	privGroupNames := []string{"Domain Admins", "Enterprise Admins", "Schema Admins"}
	for _, name := range privGroupNames {
		dn := fmt.Sprintf("CN=%s,CN=Users,%s", name, c.baseDN)
		criticalObjects = append(criticalObjects, struct{ dn, objType string }{dn, "Group"})
	}

	for _, obj := range criticalObjects {
		aclData := c.readObjectACL(obj.dn, obj.objType)
		if aclData != nil {
			acls = append(acls, aclData)
		}
	}

	// Check for accounts with DCSync rights on the domain root
	// DCSync requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
	// We detect this by checking for these extended rights in the domain DACL
	dcSyncAccounts := c.findDCSyncAccounts()

	return map[string]interface{}{
		"acls":           acls,
		"dcsync_capable": dcSyncAccounts,
	}, nil
}

func (c *Collector) readObjectACL(dn, objType string) interface{} {
	// Request nTSecurityDescriptor with DACL flag
	// Control OID 1.2.840.113556.1.4.801 = LDAP_SERVER_SD_FLAGS_OID
	// Value 0x07 = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION
	sdControl := buildSDFlagsControl(7)

	sr := newSearchRequest(dn, "(objectClass=*)", []string{"nTSecurityDescriptor", "sAMAccountName", "name"})
	sr.Controls = []ldapControl{sdControl}

	res, err := c.conn.Search(sr.toLDAP())
	if err != nil || len(res.Entries) == 0 {
		return nil
	}

	e := res.Entries[0]
	sdRaw := e.GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdRaw) == 0 {
		return nil
	}

	entries := parseSecurityDescriptor(sdRaw)
	name := e.GetAttributeValue("sAMAccountName")
	if name == "" {
		name = e.GetAttributeValue("name")
	}

	return map[string]interface{}{
		"object_dn":   dn,
		"object_type": objType,
		"name":        name,
		"entries":     entries,
	}
}

// findDCSyncAccounts looks for accounts with replication extended rights on the domain object.
func (c *Collector) findDCSyncAccounts() []interface{} {
	// Query the domain object's security descriptor
	sdRaw := c.getDomainSD()
	if sdRaw == nil {
		return nil
	}

	// DCSync extended rights GUIDs (in object GUID format)
	dcSyncRights := map[string]bool{
		"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": true, // DS-Replication-Get-Changes
		"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": true, // DS-Replication-Get-Changes-All
	}

	aces := parseSecurityDescriptor(sdRaw)
	var capable []interface{}
	for _, aceIface := range aces {
		ace, ok := aceIface.(map[string]interface{})
		if !ok {
			continue
		}
		objType, _ := ace["object_type"].(string)
		if dcSyncRights[strings.ToLower(objType)] {
			capable = append(capable, ace)
		}
	}
	return capable
}

func (c *Collector) getDomainSD() []byte {
	sdControl := buildSDFlagsControl(4) // DACL only

	sr := newSearchRequest(c.baseDN, "(objectClass=domain)", []string{"nTSecurityDescriptor"})
	sr.Controls = []ldapControl{sdControl}

	res, err := c.conn.Search(sr.toLDAP())
	if err != nil || len(res.Entries) == 0 {
		return nil
	}
	return res.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
}

// ============================================================
// Security Descriptor parsing (minimal, enough for ACL checks)
// ============================================================

// parseSecurityDescriptor parses a Windows SECURITY_DESCRIPTOR binary and returns ACEs.
func parseSecurityDescriptor(sd []byte) []interface{} {
	if len(sd) < 20 {
		return nil
	}

	// SECURITY_DESCRIPTOR header:
	// revision(1) sbz1(1) control(2) offsetOwner(4) offsetGroup(4) offsetSacl(4) offsetDacl(4)
	daclOffset := int(binary.LittleEndian.Uint32(sd[16:20]))
	if daclOffset == 0 || daclOffset >= len(sd) {
		return nil
	}

	return parseACL(sd[daclOffset:])
}

func parseACL(acl []byte) []interface{} {
	if len(acl) < 8 {
		return nil
	}
	// ACL header: aclRevision(1) sbz1(1) aclSize(2) aceCount(2) sbz2(2)
	aceCount := int(binary.LittleEndian.Uint16(acl[4:6]))
	offset := 8

	var aces []interface{}
	for i := 0; i < aceCount && offset < len(acl); i++ {
		ace := parseACE(acl[offset:])
		if ace != nil {
			aces = append(aces, ace)
		}
		// ACE size at offset 2-3 in the ACE header
		if offset+3 >= len(acl) {
			break
		}
		aceSize := int(binary.LittleEndian.Uint16(acl[offset+2 : offset+4]))
		if aceSize < 4 {
			break
		}
		offset += aceSize
	}
	return aces
}

func parseACE(ace []byte) interface{} {
	if len(ace) < 8 {
		return nil
	}
	// ACE header: type(1) flags(1) size(2)
	aceType := int(ace[0])
	aceSize := int(binary.LittleEndian.Uint16(ace[2:4]))
	if aceSize > len(ace) {
		return nil
	}

	// ACCESS_ALLOWED_ACE(0), ACCESS_DENIED_ACE(1),
	// ACCESS_ALLOWED_OBJECT_ACE(5), ACCESS_DENIED_OBJECT_ACE(6)
	var accessType string
	switch aceType {
	case 0, 5:
		accessType = "Allow"
	case 1, 6:
		accessType = "Deny"
	default:
		return nil
	}

	// Access mask at offset 4
	if len(ace) < 8 {
		return nil
	}
	accessMask := binary.LittleEndian.Uint32(ace[4:8])
	rights := decodeAccessMask(accessMask)

	// SID starts at offset 8 for basic ACEs, offset 8+8 or 8+24 for object ACEs
	sidOffset := 8
	objectTypeGUID := ""
	if aceType == 5 || aceType == 6 {
		// Object ACE: flags(4), objectType GUID(16, optional), inheritedType GUID(16, optional), SID
		if len(ace) < 12 {
			return nil
		}
		objectFlags := binary.LittleEndian.Uint32(ace[8:12])
		sidOffset = 12
		if objectFlags&0x1 != 0 && len(ace) >= sidOffset+16 { // ACE_OBJECT_TYPE_PRESENT
			objectTypeGUID = formatGUIDFromBytes(ace[sidOffset : sidOffset+16])
			sidOffset += 16
		}
		if objectFlags&0x2 != 0 && len(ace) >= sidOffset+16 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
			sidOffset += 16
		}
	}

	if sidOffset >= len(ace) {
		return nil
	}
	trusteeSID := decodeSID(ace[sidOffset:])

	return map[string]interface{}{
		"access_type": accessType,
		"rights":      rights,
		"trustee_sid": trusteeSID,
		"object_type": objectTypeGUID,
		"is_inherited": ace[1]&0x10 != 0, // INHERITED_ACE flag
	}
}

func decodeAccessMask(mask uint32) string {
	var rights []string
	if mask&0x10000000 != 0 {
		rights = append(rights, "GenericAll")
	}
	if mask&0x00040000 != 0 {
		rights = append(rights, "WriteDACL")
	}
	if mask&0x00080000 != 0 {
		rights = append(rights, "WriteOwner")
	}
	if mask&0x00020000 != 0 {
		rights = append(rights, "ReadControl")
	}
	if mask&0x20000000 != 0 {
		rights = append(rights, "GenericWrite")
	}
	if mask&0x00000100 != 0 {
		rights = append(rights, "ExtendedRight")
	}
	if mask&0x00000008 != 0 {
		rights = append(rights, "WriteProperty")
	}
	if len(rights) == 0 {
		return fmt.Sprintf("0x%08X", mask)
	}
	return strings.Join(rights, "|")
}

func formatGUIDFromBytes(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8:10], b[10:16],
	)
}

// ============================================================
// LDAP control helpers (to request nTSecurityDescriptor)
// ============================================================

type ldapControl struct {
	OID      string
	Critical bool
	Value    []byte
}

// buildSDFlagsControl creates the LDAP_SERVER_SD_FLAGS_OID control.
// flags: 1=Owner, 2=Group, 4=DACL, 8=SACL
func buildSDFlagsControl(flags uint32) ldapControl {
	// BER encoding of an integer: 0x30 0x03 0x02 0x01 <flags>
	val := []byte{0x30, 0x03, 0x02, 0x01, byte(flags)}
	return ldapControl{
		OID:      "1.2.840.113556.1.4.801",
		Critical: true,
		Value:    val,
	}
}

type searchRequestWrapper struct {
	BaseDN  string
	Filter  string
	Attrs   []string
	Controls []ldapControl
}

func newSearchRequest(baseDN, filter string, attrs []string) *searchRequestWrapper {
	return &searchRequestWrapper{BaseDN: baseDN, Filter: filter, Attrs: attrs}
}

func (s *searchRequestWrapper) toLDAP() *ldap.SearchRequest {
	var controls []ldap.Control
	for _, c := range s.Controls {
		controls = append(controls, ldap.NewControlString(c.OID, c.Critical, string(c.Value)))
	}
	return &ldap.SearchRequest{
		BaseDN:       s.BaseDN,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    30,
		TypesOnly:    false,
		Filter:       s.Filter,
		Attributes:   s.Attrs,
		Controls:     controls,
	}
}
