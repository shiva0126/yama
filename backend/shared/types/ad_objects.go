package types

import "time"

// ============================================================
// Forest & Domain Topology
// ============================================================

type ADForest struct {
	Name            string      `json:"name"`
	RootDomain      string      `json:"root_domain"`
	FunctionalLevel int         `json:"functional_level"` // 0=2000, 2=2003, 3=2008, 4=2008R2, 5=2012, 6=2012R2, 7=2016
	Domains         []ADDomain  `json:"domains"`
	Trusts          []ADTrust   `json:"trusts"`
	GlobalCatalogs  []string    `json:"global_catalogs"`
	Sites           []ADSite    `json:"sites"`
	SchemaVersion   int         `json:"schema_version"`
	CollectedAt     time.Time   `json:"collected_at"`
}

type ADDomain struct {
	DistinguishedName string   `json:"distinguished_name"`
	Name              string   `json:"name"`    // FQDN
	NetBIOS           string   `json:"netbios"` // Short name
	Forest            string   `json:"forest"`
	FunctionalLevel   int      `json:"functional_level"`
	DomainSID         string   `json:"domain_sid"`
	PDCEmulator       string   `json:"pdc_emulator"`
	RIDMaster         string   `json:"rid_master"`
	InfrastructureMaster string `json:"infrastructure_master"`
	DomainControllers []string `json:"domain_controllers"`
	ChildDomains      []string `json:"child_domains"`
	ParentDomain      string   `json:"parent_domain"`
	TombstoneLifetime int      `json:"tombstone_lifetime"` // days
	MaxPwdAge         int64    `json:"max_pwd_age"`        // ticks
	MinPwdAge         int64    `json:"min_pwd_age"`
	MinPwdLength      int      `json:"min_pwd_length"`
	PwdHistoryLength  int      `json:"pwd_history_length"`
	LockoutThreshold  int      `json:"lockout_threshold"`
	LockoutDuration   int64    `json:"lockout_duration"`
}

type ADTrust struct {
	SourceDomain  string `json:"source_domain"`
	TargetDomain  string `json:"target_domain"`
	TrustType     string `json:"trust_type"`      // External, Forest, Kerberos, MIT, DCE
	TrustDirection string `json:"trust_direction"` // Inbound, Outbound, Bidirectional
	TrustAttributes int   `json:"trust_attributes"`
	IsTransitive  bool   `json:"is_transitive"`
	SIDFiltering  bool   `json:"sid_filtering"`
	SelectiveAuth bool   `json:"selective_auth"`
}

type ADSite struct {
	Name    string   `json:"name"`
	Subnets []string `json:"subnets"`
	DCs     []string `json:"dcs"`
}

// ============================================================
// Users
// ============================================================

type ADUser struct {
	DistinguishedName      string    `json:"distinguished_name"`
	SamAccountName         string    `json:"sam_account_name"`
	UserPrincipalName      string    `json:"user_principal_name"`
	DisplayName            string    `json:"display_name"`
	GivenName              string    `json:"given_name"`
	Surname                string    `json:"surname"`
	EmailAddress           string    `json:"email_address"`
	Department             string    `json:"department"`
	Title                  string    `json:"title"`
	Description            string    `json:"description"`
	Domain                 string    `json:"domain"`
	ObjectSID              string    `json:"object_sid"`
	ObjectGUID             string    `json:"object_guid"`

	// Account flags
	Enabled                bool      `json:"enabled"`
	Locked                 bool      `json:"locked"`
	PasswordNeverExpires   bool      `json:"password_never_expires"`
	PasswordNotRequired    bool      `json:"password_not_required"`
	PasswordExpired        bool      `json:"password_expired"`
	CannotChangePassword   bool      `json:"cannot_change_password"`
	ReversibleEncryption   bool      `json:"reversible_encryption"`
	SmartcardRequired      bool      `json:"smartcard_required"`
	TrustedForDelegation   bool      `json:"trusted_for_delegation"`   // Unconstrained delegation
	TrustedToAuthForDelegation bool  `json:"trusted_to_auth_for_delegation"` // Protocol transition
	DontRequirePreauth     bool      `json:"dont_require_preauth"`     // AS-REP roastable
	UseDesKeyOnly          bool      `json:"use_des_key_only"`
	AdminCount             int       `json:"admin_count"` // adminCount=1 means protected by SDProp

	// Timestamps
	Created                time.Time `json:"created"`
	Modified               time.Time `json:"modified"`
	LastLogon              time.Time `json:"last_logon"`
	LastLogonTimestamp     time.Time `json:"last_logon_timestamp"`
	PwdLastSet             time.Time `json:"pwd_last_set"`
	AccountExpires         time.Time `json:"account_expires"`

	// Memberships & SPNs
	MemberOf               []string  `json:"member_of"`
	ServicePrincipalNames  []string  `json:"service_principal_names"` // Kerberoastable if non-empty
	AllowedToDelegateTo    []string  `json:"allowed_to_delegate_to"`  // Constrained delegation targets

	// Privilege indicators
	IsPrivileged           bool      `json:"is_privileged"`
	PrivilegedGroups       []string  `json:"privileged_groups"`
	IsServiceAccount       bool      `json:"is_service_account"`
	IsMSA                  bool      `json:"is_msa"`   // Managed Service Account
	IsGMSA                 bool      `json:"is_gmsa"`  // Group Managed Service Account
	IsDCSyncCapable        bool      `json:"is_dcsync_capable"`
	HasShadowCredentials   bool      `json:"has_shadow_credentials"` // msDS-KeyCredentialLink set

	// UAC raw value
	UserAccountControl     int       `json:"user_account_control"`
}

// ============================================================
// Groups
// ============================================================

type ADGroup struct {
	DistinguishedName string   `json:"distinguished_name"`
	SamAccountName    string   `json:"sam_account_name"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Domain            string   `json:"domain"`
	ObjectSID         string   `json:"object_sid"`
	GroupScope        string   `json:"group_scope"`    // DomainLocal, Global, Universal
	GroupCategory     string   `json:"group_category"` // Security, Distribution
	Members           []string `json:"members"`
	MemberOf          []string `json:"member_of"`
	NestedGroups      []string `json:"nested_groups"`
	AdminCount        int      `json:"admin_count"`
	IsPrivileged      bool     `json:"is_privileged"`
	PrivilegeLevel    string   `json:"privilege_level"` // Tier0, Tier1, Tier2
	Created           time.Time `json:"created"`
	Modified          time.Time `json:"modified"`
}

// Privileged built-in groups to track
var PrivilegedGroupSIDs = map[string]string{
	"S-1-5-32-544":             "Administrators",
	"S-1-5-32-548":             "Account Operators",
	"S-1-5-32-549":             "Server Operators",
	"S-1-5-32-550":             "Print Operators",
	"S-1-5-32-551":             "Backup Operators",
	"S-1-5-32-552":             "Replicators",
	"-512":                     "Domain Admins",       // RID-relative
	"-518":                     "Schema Admins",
	"-519":                     "Enterprise Admins",
	"-516":                     "Domain Controllers",
	"-498":                     "Enterprise Read-Only DCs",
	"-521":                     "Read-Only Domain Controllers",
	"-526":                     "Key Admins",
	"-527":                     "Enterprise Key Admins",
	"S-1-5-32-574":             "Certificate Service DCOM Access",
}

// ============================================================
// Computers
// ============================================================

type ADComputer struct {
	DistinguishedName     string    `json:"distinguished_name"`
	SamAccountName        string    `json:"sam_account_name"`
	Name                  string    `json:"name"`
	DNSHostName           string    `json:"dns_host_name"`
	Domain                string    `json:"domain"`
	ObjectSID             string    `json:"object_sid"`
	OperatingSystem       string    `json:"operating_system"`
	OperatingSystemVersion string   `json:"operating_system_version"`
	ServicePack           string    `json:"service_pack"`
	Enabled               bool      `json:"enabled"`
	IsDomainController    bool      `json:"is_domain_controller"`
	IsReadOnlyDC          bool      `json:"is_read_only_dc"`
	Site                  string    `json:"site"`

	// Delegation
	TrustedForDelegation       bool     `json:"trusted_for_delegation"`        // Unconstrained
	TrustedToAuthForDelegation bool     `json:"trusted_to_auth_for_delegation"` // Constrained + protocol transition
	AllowedToDelegateTo        []string `json:"allowed_to_delegate_to"`

	// LAPS
	LAPSEnabled           bool      `json:"laps_enabled"`
	LAPSExpiration        time.Time `json:"laps_expiration"`

	// Timestamps
	Created               time.Time `json:"created"`
	Modified              time.Time `json:"modified"`
	LastLogon             time.Time `json:"last_logon"`
	LastLogonTimestamp    time.Time `json:"last_logon_timestamp"`
	PwdLastSet            time.Time `json:"pwd_last_set"`

	MemberOf              []string  `json:"member_of"`
	ServicePrincipalNames []string  `json:"service_principal_names"`
	UserAccountControl    int       `json:"user_account_control"`
}

// ============================================================
// Domain Controllers
// ============================================================

type ADDomainController struct {
	Name                string    `json:"name"`
	HostName            string    `json:"host_name"`
	IPAddress           string    `json:"ip_address"`
	Site                string    `json:"site"`
	Domain              string    `json:"domain"`
	Forest              string    `json:"forest"`
	OperatingSystem     string    `json:"operating_system"`
	OSVersion           string    `json:"os_version"`
	IsReadOnly          bool      `json:"is_read_only"`
	IsGlobalCatalog     bool      `json:"is_global_catalog"`
	FSMORoles           []string  `json:"fsmo_roles"`

	// Services status
	SpoolerRunning      bool      `json:"spooler_running"`
	WDigestEnabled      bool      `json:"wdigest_enabled"`
	SMBSigningEnabled   bool      `json:"smb_signing_enabled"`
	SMBSigningRequired  bool      `json:"smb_signing_required"`
	LDAPSigningRequired bool      `json:"ldap_signing_required"`
	NTLMRestricted      bool      `json:"ntlm_restricted"`

	// Replication
	LastReplication     time.Time `json:"last_replication"`
	ReplicationErrors   int       `json:"replication_errors"`
	ReplicationPartners []string  `json:"replication_partners"`

	// Timestamps
	LastLogon           time.Time `json:"last_logon"`
}

// ============================================================
// Group Policy Objects
// ============================================================

type ADGPO struct {
	ID              string    `json:"id"`   // GUID
	Name            string    `json:"name"`
	Domain          string    `json:"domain"`
	DisplayName     string    `json:"display_name"`
	Status          string    `json:"status"` // AllSettingsEnabled, ComputerSettingsDisabled, UserSettingsDisabled, AllSettingsDisabled
	Created         time.Time `json:"created"`
	Modified        time.Time `json:"modified"`
	LinkedOUs       []GPOLink `json:"linked_ous"`
	IsLinked        bool      `json:"is_linked"`
	ComputerVersion int       `json:"computer_version"`
	UserVersion     int       `json:"user_version"`

	// Key settings extracted
	PasswordPolicy      *PasswordPolicy      `json:"password_policy,omitempty"`
	AccountLockout      *AccountLockoutPolicy `json:"account_lockout,omitempty"`
	AuditPolicy         *AuditPolicy         `json:"audit_policy,omitempty"`
	SecuritySettings    *SecuritySettings    `json:"security_settings,omitempty"`

	// Permissions
	Owner           string   `json:"owner"`
	Permissions     []GPOPermission `json:"permissions"`
	SYSVOLWritable  bool     `json:"sysvol_writable_by_nonadmin"`
}

type GPOLink struct {
	OUDN    string `json:"ou_dn"`
	Enabled bool   `json:"enabled"`
	Enforced bool  `json:"enforced"`
}

type GPOPermission struct {
	Trustee    string `json:"trustee"`
	Permission string `json:"permission"` // Read, Write, Create, Delete, ApplyGroupPolicy, FullControl
	Inherited  bool   `json:"inherited"`
}

type PasswordPolicy struct {
	MinPasswordLength     int   `json:"min_password_length"`
	PasswordHistoryCount  int   `json:"password_history_count"`
	MaxPasswordAge        int64 `json:"max_password_age"`
	MinPasswordAge        int64 `json:"min_password_age"`
	ComplexityEnabled     bool  `json:"complexity_enabled"`
	ReversibleEncryption  bool  `json:"reversible_encryption"`
}

type AccountLockoutPolicy struct {
	LockoutThreshold      int   `json:"lockout_threshold"`
	LockoutDuration       int64 `json:"lockout_duration"`
	ObservationWindow     int64 `json:"observation_window"`
}

type AuditPolicy struct {
	AccountLogon         string `json:"account_logon"`
	AccountManagement    string `json:"account_management"`
	DirectoryService     string `json:"directory_service"`
	LogonEvents          string `json:"logon_events"`
	ObjectAccess         string `json:"object_access"`
	PolicyChange         string `json:"policy_change"`
	PrivilegeUse         string `json:"privilege_use"`
	SystemEvents         string `json:"system_events"`
}

type SecuritySettings struct {
	LMAuthenticationLevel   int    `json:"lm_authentication_level"`
	RestrictNTLM            int    `json:"restrict_ntlm"`
	WDigestAuthentication   bool   `json:"wdigest_authentication"`
	LSAProtection           bool   `json:"lsa_protection"`
	CredentialGuard         bool   `json:"credential_guard"`
	SMBv1Enabled            bool   `json:"smbv1_enabled"`
	PrintSpoolerDisabled    bool   `json:"print_spooler_disabled"`
	LDAPSRequired           bool   `json:"ldaps_required"`
}

// ============================================================
// Kerberos Configuration
// ============================================================

type KerberosConfig struct {
	Domain                  string    `json:"domain"`
	KrbtgtPasswordLastSet   time.Time `json:"krbtgt_password_last_set"`
	KrbtgtPasswordAge       int       `json:"krbtgt_password_age_days"`
	SupportedEncTypes       []string  `json:"supported_enc_types"`
	DESEnabled              bool      `json:"des_enabled"`
	RC4Enabled              bool      `json:"rc4_enabled"`
	AESEnabled              bool      `json:"aes_enabled"`
	MaxTicketAge            int       `json:"max_ticket_age_hours"`
	MaxRenewAge             int       `json:"max_renew_age_days"`
	MaxClockSkew            int       `json:"max_clock_skew_minutes"`
}

// ============================================================
// ACL / Permissions
// ============================================================

type ADACL struct {
	ObjectDN     string       `json:"object_dn"`
	ObjectType   string       `json:"object_type"`
	Owner        string       `json:"owner"`
	Entries      []ACLEntry   `json:"entries"`
}

type ACLEntry struct {
	Trustee          string `json:"trustee"`
	TrusteeSID       string `json:"trustee_sid"`
	AccessType       string `json:"access_type"`        // Allow, Deny
	Rights           string `json:"rights"`              // GenericAll, WriteDACL, etc.
	InheritanceType  string `json:"inheritance_type"`
	ObjectType       string `json:"object_type"`         // GUID of extended right
	IsInherited      bool   `json:"is_inherited"`
	IsDangerous      bool   `json:"is_dangerous"`
	DangerReason     string `json:"danger_reason"`
}

// Dangerous rights that enable privilege escalation
var DangerousRights = map[string]string{
	"GenericAll":            "Full control over object",
	"WriteDACL":             "Can modify permissions (leads to full control)",
	"WriteOwner":            "Can take ownership (leads to full control)",
	"GenericWrite":          "Can write to most attributes",
	"WriteProperty":         "Can write specific properties",
	"ExtendedRight":         "Extended rights (DCSync, Reset Password, etc.)",
	"Self":                  "Self-write access",
	"AllExtendedRights":     "All extended rights including DCSync",
}

// Extended rights GUIDs
var ExtendedRights = map[string]string{
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
	"89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
	"00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
	"ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
}

// ============================================================
// Organizational Units
// ============================================================

type ADOU struct {
	DistinguishedName string    `json:"distinguished_name"`
	Name              string    `json:"name"`
	Domain            string    `json:"domain"`
	Description       string    `json:"description"`
	Created           time.Time `json:"created"`
	Modified          time.Time `json:"modified"`
	LinkedGPOs        []string  `json:"linked_gpos"`
	ChildOUs          []string  `json:"child_ous"`
	ObjectCount       int       `json:"object_count"`
}

// ============================================================
// Fine-Grained Password Policies
// ============================================================

type FineGrainedPasswordPolicy struct {
	Name                  string   `json:"name"`
	DistinguishedName     string   `json:"distinguished_name"`
	Precedence            int      `json:"precedence"`
	AppliesToGroups       []string `json:"applies_to_groups"`
	AppliesToUsers        []string `json:"applies_to_users"`
	PasswordPolicy        PasswordPolicy        `json:"password_policy"`
	AccountLockoutPolicy  AccountLockoutPolicy  `json:"account_lockout_policy"`
}

// ============================================================
// ADCS – Active Directory Certificate Services
// ============================================================

type ADCertificateTemplate struct {
	Name                    string   `json:"name"`
	DisplayName             string   `json:"display_name"`
	DistinguishedName       string   `json:"distinguished_name"`
	OID                     string   `json:"oid"`
	SchemaVersion           int      `json:"schema_version"`
	ValidityPeriod          string   `json:"validity_period"`
	RenewalPeriod           string   `json:"renewal_period"`

	// Enrollment flags (msPKI-Enrollment-Flag)
	EnrolleeSuppliesSubject bool     `json:"enrollee_supplies_subject"` // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
	NoSecurityExtension     bool     `json:"no_security_extension"`     // CT_FLAG_NO_SECURITY_EXTENSION = 0x80000
	ReqManagerApproval      bool     `json:"requires_manager_approval"` // CT_FLAG_PEND_ALL_REQUESTS = 0x2

	// Key usage / EKU
	ExtendedKeyUsage        []string `json:"extended_key_usage"`
	HasClientAuth           bool     `json:"has_client_auth"`
	HasAnyPurpose           bool     `json:"has_any_purpose"`
	HasCertRequestAgent     bool     `json:"has_cert_request_agent"`

	// Access control
	EnrollableBy            []string `json:"enrollable_by"`   // principals with Enroll right
	WriteableBy             []string `json:"writeable_by"`    // principals with write access
	LowPrivEnrollment       bool     `json:"low_priv_enrollment"` // Authenticated Users / Domain Computers can enroll

	// ESC classification
	VulnerableESC1          bool     `json:"vulnerable_esc1"`  // Enrollee supplies SAN + client auth + low-priv enroll
	VulnerableESC2          bool     `json:"vulnerable_esc2"`  // Any Purpose or SubCA
	VulnerableESC3          bool     `json:"vulnerable_esc3"`  // Certificate Request Agent
	VulnerableESC4          bool     `json:"vulnerable_esc4"`  // Low-priv write access to template
}

type ADCertificateAuthority struct {
	Name                    string   `json:"name"`
	DistinguishedName       string   `json:"distinguished_name"`
	DNSHostName             string   `json:"dns_host_name"`
	Flags                   int      `json:"flags"`

	// CA flags
	UserSpecifiedSAN        bool     `json:"user_specified_san"`  // EDITF_ATTRIBUTESUBJECTALTNAME2 = ESC6
	ManageCALowPriv         bool     `json:"manage_ca_low_priv"`  // Low-priv ManageCA = ESC7

	// ACL
	ACLEntries              []ACLEntry `json:"acl_entries"`

	// Published templates
	Templates               []string `json:"templates"`

	// Web enrollment endpoint (for ESC8)
	WebEnrollmentEnabled    bool     `json:"web_enrollment_enabled"`
}

// ============================================================
// Sites & Subnets
// ============================================================

type ADSiteDetailed struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Subnets     []ADSubnet  `json:"subnets"`
	SiteLinks   []string    `json:"site_links"`
	DCs         []string    `json:"dcs"`
}

type ADSubnet struct {
	Name        string `json:"name"` // e.g. 192.168.1.0/24
	SiteName    string `json:"site_name"`
	Description string `json:"description"`
}

type ADSiteLink struct {
	Name        string   `json:"name"`
	Sites       []string `json:"sites"`
	Cost        int      `json:"cost"`
	Interval    int      `json:"replication_interval_minutes"`
}

// ============================================================
// Inventory Snapshot (wraps everything for a scan)
// ============================================================

type InventorySnapshot struct {
	ID                   string                  `json:"id"`
	ScanID               string                  `json:"scan_id"`
	TakenAt              time.Time               `json:"taken_at"`
	Forest               *ADForest               `json:"forest,omitempty"`
	Domains              []ADDomain              `json:"domains,omitempty"`
	Users                []ADUser                `json:"users,omitempty"`
	Groups               []ADGroup               `json:"groups,omitempty"`
	Computers            []ADComputer            `json:"computers,omitempty"`
	DomainControllers    []ADDomainController    `json:"domain_controllers,omitempty"`
	GPOs                 []ADGPO                 `json:"gpos,omitempty"`
	OUs                  []ADOU                  `json:"ous,omitempty"`
	ACLs                 []ADACL                 `json:"acls,omitempty"`
	KerberosConfig       *KerberosConfig         `json:"kerberos_config,omitempty"`
	FGPPs                []FineGrainedPasswordPolicy `json:"fgpps,omitempty"`
	Trusts               []ADTrust               `json:"trusts,omitempty"`
	CertTemplates        []ADCertificateTemplate `json:"cert_templates,omitempty"`
	CertAuthorities      []ADCertificateAuthority `json:"cert_authorities,omitempty"`
	Sites                []ADSiteDetailed        `json:"sites,omitempty"`
	SiteLinks            []ADSiteLink            `json:"site_links,omitempty"`
	MachineAccountQuota  int                     `json:"machine_account_quota"`
	RecycleBinEnabled    bool                    `json:"recycle_bin_enabled"`
}
