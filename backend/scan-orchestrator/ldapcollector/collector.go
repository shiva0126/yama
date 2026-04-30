// Package ldapcollector queries Active Directory directly via LDAP (port 389).
// No Windows agent or firewall changes required — any authenticated domain user
// account can read all the attributes collected here.
package ldapcollector

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// Collector holds an authenticated LDAP connection to a domain controller.
type Collector struct {
	conn         *ldap.Conn
	baseDN       string // DC=migratesuccess,DC=local
	domain       string // migratesuccess.local
	dcIP         string
	configDN     string // CN=Configuration,DC=...
	schemaDN     string // CN=Schema,CN=Configuration,...
	privilegedDNs map[string]string // lower(dn) -> group name
}

// New dials the DC on LDAP port 389, binds with the given credentials, and
// queries rootDSE to build the base DNs.
func New(dcIP, domain, username, password string) (*Collector, error) {
	conn, err := ldap.DialURL(
		fmt.Sprintf("ldap://%s:389", dcIP),
		ldap.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}),
	)
	if err != nil {
		return nil, fmt.Errorf("LDAP dial failed: %w", err)
	}
	conn.SetTimeout(60 * time.Second)

	// Bind — try UPN format first, then DOMAIN\user
	bindDN := fmt.Sprintf("%s@%s", username, domain)
	if err := conn.Bind(bindDN, password); err != nil {
		bindDN = fmt.Sprintf("%s\\%s", strings.ToUpper(strings.Split(domain, ".")[0]), username)
		if err2 := conn.Bind(bindDN, password); err2 != nil {
			conn.Close()
			return nil, fmt.Errorf("LDAP bind failed: %w", err)
		}
	}

	// Query rootDSE (anonymous-readable) to get naming contexts
	rse, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "configurationNamingContext", "schemaNamingContext"},
		nil,
	))
	if err != nil || len(rse.Entries) == 0 {
		conn.Close()
		return nil, fmt.Errorf("rootDSE query failed: %w", err)
	}
	e := rse.Entries[0]

	baseDN := e.GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		baseDN = domainToBaseDN(domain)
	}
	configDN := e.GetAttributeValue("configurationNamingContext")
	schemaDN := e.GetAttributeValue("schemaNamingContext")

	c := &Collector{
		conn:          conn,
		baseDN:        baseDN,
		domain:        domain,
		dcIP:          dcIP,
		configDN:      configDN,
		schemaDN:      schemaDN,
		privilegedDNs: map[string]string{},
	}

	c.buildPrivilegedGroupSet()
	return c, nil
}

// Close releases the LDAP connection.
func (c *Collector) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Collect dispatches to the appropriate collector for the given task type.
// Returns a map[string]interface{} matching the format expected by the inventory service.
func (c *Collector) Collect(taskType string) (map[string]interface{}, error) {
	switch taskType {
	case "topology":
		return c.CollectTopology()
	case "users":
		return c.CollectUsers()
	case "groups":
		return c.CollectGroups()
	case "computers":
		return c.CollectComputers()
	case "gpos":
		return c.CollectGPOs()
	case "kerberos":
		return c.CollectKerberos()
	case "acls":
		return c.CollectACLs()
	case "dcinfo":
		return c.CollectDCInfo()
	case "trusts":
		return c.CollectTrusts()
	case "ous":
		return c.CollectOUs()
	case "fgpp":
		return c.CollectFGPP()
	case "adcs":
		return c.CollectADCS()
	case "sites":
		return c.CollectSites()
	default:
		return map[string]interface{}{}, nil
	}
}

// ============================================================
// Utilities
// ============================================================

// domainToBaseDN converts "corp.example.com" → "DC=corp,DC=example,DC=com".
func domainToBaseDN(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

// search performs a paged LDAP search and returns all entries.
func (c *Collector) search(base, filter string, attrs []string) ([]*ldap.Entry, error) {
	sr := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter, attrs, nil,
	)
	res, err := c.conn.SearchWithPaging(sr, 1000)
	if err != nil {
		return nil, err
	}
	return res.Entries, nil
}

// searchBase does a base-object search (single entry).
func (c *Collector) searchBase(dn, filter string, attrs []string) (*ldap.Entry, error) {
	sr := ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)
	res, err := c.conn.Search(sr)
	if err != nil || len(res.Entries) == 0 {
		return nil, err
	}
	return res.Entries[0], nil
}

// attr helpers — safe attribute reads
func attrStr(e *ldap.Entry, name string) string  { return e.GetAttributeValue(name) }
func attrVals(e *ldap.Entry, name string) []string { return e.GetAttributeValues(name) }

func attrInt(e *ldap.Entry, name string) int {
	v := e.GetAttributeValue(name)
	if v == "" {
		return 0
	}
	n, _ := strconv.Atoi(v)
	return n
}

func attrInt64(e *ldap.Entry, name string) int64 {
	v := e.GetAttributeValue(name)
	if v == "" {
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

// winTime converts a Windows FILETIME (100-ns intervals since 1601-01-01) to time.Time.
func winTime(v int64) time.Time {
	if v <= 0 || v == 9223372036854775807 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000 // 100-ns intervals 1601→1970
	return time.Unix(0, (v-epochDiff)*100).UTC()
}

func winTimeStr(e *ldap.Entry, name string) time.Time {
	return winTime(attrInt64(e, name))
}

// uac checks a UserAccountControl bit flag.
func uac(e *ldap.Entry, flag int) bool {
	return attrInt(e, "userAccountControl")&flag != 0
}

// decodeSID converts a binary objectSid to its string form S-1-5-...
func decodeSID(raw []byte) string {
	if len(raw) < 8 {
		return ""
	}
	revision := raw[0]
	subCount := int(raw[1])
	var authority int64
	for i := 2; i < 8; i++ {
		authority = authority*256 + int64(raw[i])
	}
	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subCount && 8+i*4+4 <= len(raw); i++ {
		sub := binary.LittleEndian.Uint32(raw[8+i*4:])
		sid += fmt.Sprintf("-%d", sub)
	}
	return sid
}

func attrSID(e *ldap.Entry, name string) string {
	raw := e.GetRawAttributeValue(name)
	return decodeSID(raw)
}

// decodeGUID converts a binary objectGUID to its string form.
func decodeGUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%x",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		raw[8:10],
		raw[10:16],
	)
}

func attrGUID(e *ldap.Entry, name string) string {
	return decodeGUID(e.GetRawAttributeValue(name))
}

// UserAccountControl flag constants
const (
	UACDisabled             = 0x0002
	UACPasswdNotReqd        = 0x0020
	UACReversibleEncryption = 0x0080
	UACNormalAccount        = 0x0200
	UACDontExpirePasswd     = 0x10000
	UACSmartcardRequired    = 0x40000
	UACTrustedForDelegation = 0x80000
	UACNotDelegated         = 0x100000
	UACUseDesKeyOnly        = 0x200000
	UACDontRequirePreauth   = 0x400000
	UACPasswordExpired      = 0x800000
	UACTrustedToAuth        = 0x1000000 // protocol transition
	UACServerTrustAccount   = 0x2000    // computer is DC
)

// privileged group names — if a user's memberOf contains one of these CN=..., they're privileged
var privilegedGroupNames = []string{
	"Domain Admins", "Enterprise Admins", "Schema Admins",
	"Administrators", "Account Operators", "Backup Operators",
	"Print Operators", "Server Operators", "Key Admins",
	"Enterprise Key Admins", "Group Policy Creator Owners",
	"DnsAdmins", "Protected Users",
}

// buildPrivilegedGroupSet pre-builds a set of privileged group DNs from the directory.
func (c *Collector) buildPrivilegedGroupSet() {
	for _, name := range privilegedGroupNames {
		// construct a likely DN to check — we'll also do substring match in isPrivileged
		c.privilegedDNs[strings.ToLower("CN="+name)] = name
	}
}

// isPrivileged returns true + group names if the memberOf list contains any privileged group.
func isPrivileged(memberOf []string) (bool, []string) {
	var found []string
	for _, mo := range memberOf {
		moLower := strings.ToLower(mo)
		for _, name := range privilegedGroupNames {
			if strings.Contains(moLower, strings.ToLower("CN="+name+",")) {
				found = append(found, name)
				break
			}
		}
	}
	return len(found) > 0, found
}
