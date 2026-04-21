package types

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 25
	case SeverityHigh:
		return 15
	case SeverityMedium:
		return 8
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

type FindingCategory string

const (
	CategoryKerberos        FindingCategory = "Kerberos"
	CategoryAccounts        FindingCategory = "Account Security"
	CategoryPrivileged      FindingCategory = "Privileged Access"
	CategoryGroupPolicy     FindingCategory = "Group Policy"
	CategoryDomainControllers FindingCategory = "Domain Controllers"
	CategoryADStructure     FindingCategory = "AD Structure"
	CategoryDelegation      FindingCategory = "Delegation"
	CategoryTrusts          FindingCategory = "Trusts"
)

type Finding struct {
	ID               string          `json:"id"`
	ScanID           string          `json:"scan_id"`
	IndicatorID      string          `json:"indicator_id"` // e.g., K001, A003
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Severity         Severity        `json:"severity"`
	Category         FindingCategory `json:"category"`
	RiskScore        int             `json:"risk_score"`    // 0-100
	AffectedObjects  []AffectedObject `json:"affected_objects"`
	Remediation      string          `json:"remediation"`
	References       []string        `json:"references"`
	MITRE            []string        `json:"mitre"`        // MITRE ATT&CK technique IDs
	DetectedAt       time.Time       `json:"detected_at"`
	IsNew            bool            `json:"is_new"`       // Compared to previous scan
}

type AffectedObject struct {
	DN         string `json:"dn"`
	Type       string `json:"type"`   // User, Group, Computer, GPO, DC, Domain
	Name       string `json:"name"`
	Detail     string `json:"detail"` // Extra context
}

// SecurityIndicator defines a check to run
type SecurityIndicator struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    FindingCategory `json:"category"`
	Severity    Severity        `json:"severity"`
	Remediation string          `json:"remediation"`
	References  []string        `json:"references"`
	MITRE       []string        `json:"mitre"`
}

// All defined indicators
var AllIndicators = []SecurityIndicator{
	// Kerberos
	{ID: "K001", Name: "Krbtgt password not recently reset", Category: CategoryKerberos, Severity: SeverityCritical,
		Description: "The krbtgt account password has not been reset in the last 180 days. An old krbtgt password enables Golden Ticket attacks.",
		Remediation: "Reset the krbtgt password twice (to invalidate all existing Kerberos tickets). Use the Microsoft krbtgt reset script.",
		MITRE:       []string{"T1558.001"},
		References:  []string{"https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-reset-the-krbtgt-password"}},

	{ID: "K002", Name: "Accounts with unconstrained Kerberos delegation", Category: CategoryKerberos, Severity: SeverityHigh,
		Description: "Non-DC computers or users are trusted for unconstrained delegation. An attacker who compromises these hosts can steal TGTs of any connecting user, including Domain Admins.",
		Remediation: "Remove unconstrained delegation and replace with constrained delegation or Resource-Based Constrained Delegation (RBCD). Never enable on user accounts.",
		MITRE:       []string{"T1558", "T1550.003"}},

	{ID: "K003", Name: "Accounts vulnerable to AS-REP Roasting", Category: CategoryKerberos, Severity: SeverityHigh,
		Description: "User accounts have Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH). Attackers can request AS-REP hashes and crack them offline.",
		Remediation: "Enable Kerberos pre-authentication for all accounts. If pre-auth must be disabled for a service, use a strong password.",
		MITRE:       []string{"T1558.004"}},

	{ID: "K004", Name: "User accounts with SPNs (Kerberoastable)", Category: CategoryKerberos, Severity: SeverityHigh,
		Description: "User accounts (non-computer) have Service Principal Names set. These can be targeted with Kerberoasting to obtain crackable service ticket hashes offline.",
		Remediation: "Move services to gMSA (Group Managed Service Accounts). If user SPNs are required, use strong passwords (25+ chars) and rotate regularly.",
		MITRE:       []string{"T1558.003"}},

	{ID: "K005", Name: "DES encryption enabled on accounts", Category: CategoryKerberos, Severity: SeverityMedium,
		Description: "Accounts have DES-only Kerberos encryption enabled. DES is a weak, deprecated cipher broken in hours on modern hardware.",
		Remediation: "Remove USE_DES_KEY_ONLY flag from all accounts. Ensure all systems support AES.",
		MITRE:       []string{"T1558"}},

	{ID: "K006", Name: "Constrained delegation with protocol transition", Category: CategoryKerberos, Severity: SeverityMedium,
		Description: "Accounts have constrained delegation with protocol transition (TrustedToAuthForDelegation). This allows the service to impersonate any user to the target service.",
		Remediation: "Review if protocol transition is necessary. Prefer standard constrained delegation or RBCD where possible.",
		MITRE:       []string{"T1558"}},

	// Account Security
	{ID: "A001", Name: "Users with password never expires", Category: CategoryAccounts, Severity: SeverityMedium,
		Description: "User accounts have the Password Never Expires flag set. These passwords may be very old and weak.",
		Remediation: "Remove the password never expires flag and enforce password rotation policies. Use FGPP for service accounts that require it.",
		MITRE:       []string{"T1078"}},

	{ID: "A002", Name: "Accounts with reversible password encryption", Category: CategoryAccounts, Severity: SeverityHigh,
		Description: "Accounts store passwords using reversible encryption. These passwords can be decrypted by anyone with access to the AD database (NTDS.dit).",
		Remediation: "Disable reversible encryption for all accounts. Only enable if absolutely required for specific applications.",
		MITRE:       []string{"T1003.003"}},

	{ID: "A003", Name: "Stale enabled user accounts", Category: CategoryAccounts, Severity: SeverityMedium,
		Description: "User accounts are enabled but have not logged in for more than 90 days. Stale accounts may have weak passwords and no active owner to notice suspicious activity.",
		Remediation: "Disable or delete accounts that haven't been used in 90+ days. Implement a lifecycle management process.",
		MITRE:       []string{"T1078.002"}},

	{ID: "A004", Name: "Accounts with password not required", Category: CategoryAccounts, Severity: SeverityHigh,
		Description: "Accounts have PASSWD_NOTREQD flag set, allowing empty passwords.",
		Remediation: "Remove PASSWD_NOTREQD flag. Set strong passwords and ensure password complexity is enforced.",
		MITRE:       []string{"T1078"}},

	{ID: "A005", Name: "Privileged accounts with non-expiring passwords", Category: CategoryAccounts, Severity: SeverityHigh,
		Description: "Accounts in privileged groups have Password Never Expires set. Privilege account passwords should be rotated regularly.",
		Remediation: "Enforce password expiration for all privileged accounts. Use PAM solutions for break-glass accounts.",
		MITRE:       []string{"T1078.002"}},

	{ID: "A006", Name: "Default Administrator account active", Category: CategoryAccounts, Severity: SeverityMedium,
		Description: "The built-in Administrator account (RID-500) is enabled. This well-known account is a prime target for brute-force attacks.",
		Remediation: "Rename the default Administrator account, set a complex password, and monitor for its use. Consider disabling it and using alternative admin accounts.",
		MITRE:       []string{"T1078.002"}},

	{ID: "A007", Name: "Guest account enabled", Category: CategoryAccounts, Severity: SeverityHigh,
		Description: "The built-in Guest account is enabled, allowing unauthenticated access to domain resources.",
		Remediation: "Disable the Guest account immediately.",
		MITRE:       []string{"T1078.001"}},

	{ID: "A008", Name: "Krbtgt account with old password", Category: CategoryAccounts, Severity: SeverityCritical,
		Description: "The krbtgt account password is over 180 days old.",
		Remediation: "Reset krbtgt password using Microsoft's krbtgt reset script. Perform two resets 10+ hours apart.",
		MITRE:       []string{"T1558.001"}},

	// Privileged Access
	{ID: "P001", Name: "Non-standard accounts with DCSync rights", Category: CategoryPrivileged, Severity: SeverityCritical,
		Description: "Accounts outside of Domain Admins/Domain Controllers have replication rights (DS-Replication-Get-Changes-All) which enables DCSync attacks to dump all password hashes.",
		Remediation: "Remove replication rights from all non-DC, non-DA accounts. Audit DACL on the domain root for replication extended rights.",
		MITRE:       []string{"T1003.006"}},

	{ID: "P002", Name: "Unexpected members in Domain Admins", Category: CategoryPrivileged, Severity: SeverityHigh,
		Description: "The Domain Admins group contains accounts that may not be authorized. Privileged group membership should be tightly controlled.",
		Remediation: "Review Domain Admins membership. Remove all unnecessary accounts. Implement a Just-In-Time privileged access model.",
		MITRE:       []string{"T1078.002"}},

	{ID: "P003", Name: "Schema Admins group not empty", Category: CategoryPrivileged, Severity: SeverityHigh,
		Description: "The Schema Admins group should be empty unless schema changes are being made. Persistent membership is a security risk.",
		Remediation: "Remove all members from Schema Admins. Add members only when schema modifications are required, then immediately remove.",
		MITRE:       []string{"T1078.002"}},

	{ID: "P004", Name: "Enterprise Admins group has non-standard members", Category: CategoryPrivileged, Severity: SeverityHigh,
		Description: "Enterprise Admins should only contain administrator accounts during forest-wide operations.",
		Remediation: "Empty the Enterprise Admins group. Add members only when forest-wide changes are required.",
		MITRE:       []string{"T1078.002"}},

	{ID: "P005", Name: "AdminSDHolder ACL deviations", Category: CategoryPrivileged, Severity: SeverityHigh,
		Description: "Unexpected ACEs found on the AdminSDHolder object. ACEs here propagate to all protected accounts via SDProp, potentially granting unauthorized control.",
		Remediation: "Review and clean AdminSDHolder ACL. Only legitimate admin service accounts should have rights here.",
		MITRE:       []string{"T1222.001"}},

	{ID: "P006", Name: "Accounts with GenericAll on domain", Category: CategoryPrivileged, Severity: SeverityCritical,
		Description: "Non-privileged accounts have GenericAll (full control) on the domain object, enabling complete domain compromise.",
		Remediation: "Remove GenericAll from non-admin accounts on the domain object. Audit all domain-level ACEs.",
		MITRE:       []string{"T1078", "T1003.006"}},

	// Group Policy
	{ID: "G001", Name: "No account lockout policy configured", Category: CategoryGroupPolicy, Severity: SeverityHigh,
		Description: "No account lockout policy is configured, allowing unlimited password guessing attempts.",
		Remediation: "Configure account lockout: threshold ≤5 attempts, duration ≥15 min, observation window ≥15 min.",
		MITRE:       []string{"T1110"}},

	{ID: "G002", Name: "Weak domain password policy", Category: CategoryGroupPolicy, Severity: SeverityMedium,
		Description: "The domain password policy does not meet security best practices (minimum 12 characters, complexity enabled).",
		Remediation: "Set minimum password length to 14+ characters, enable complexity, max age ≤90 days, history ≥24.",
		MITRE:       []string{"T1110.002"}},

	{ID: "G003", Name: "SYSVOL accessible with write permissions by non-admins", Category: CategoryGroupPolicy, Severity: SeverityHigh,
		Description: "Non-administrative accounts can write to SYSVOL. Malicious scripts in SYSVOL execute on all domain machines.",
		Remediation: "Restrict SYSVOL write permissions to Domain Admins and SYSTEM only.",
		MITRE:       []string{"T1484.001"}},

	{ID: "G004", Name: "GPO with no link (orphaned)", Category: CategoryGroupPolicy, Severity: SeverityLow,
		Description: "Unlinked GPOs exist in the domain. These may contain sensitive settings or be misused.",
		Remediation: "Review unlinked GPOs and either link them properly or delete if not needed.",
		MITRE:       []string{}},

	{ID: "G005", Name: "WDigest authentication enabled via GPO", Category: CategoryGroupPolicy, Severity: SeverityHigh,
		Description: "WDigest authentication is enabled, causing credentials to be stored in cleartext in LSASS memory.",
		Remediation: "Disable WDigest via GPO: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0",
		MITRE:       []string{"T1003.001"}},

	// Domain Controllers
	{ID: "DC001", Name: "Domain Controller running outdated OS", Category: CategoryDomainControllers, Severity: SeverityHigh,
		Description: "One or more Domain Controllers run an OS version that is end-of-life or below Windows Server 2016.",
		Remediation: "Upgrade or replace DCs running outdated OS versions. Target Windows Server 2022.",
		MITRE:       []string{"T1190"}},

	{ID: "DC002", Name: "Print Spooler service running on DC", Category: CategoryDomainControllers, Severity: SeverityCritical,
		Description: "The Print Spooler service is running on Domain Controllers, enabling PrintNightmare and printer-based Kerberos coercion attacks.",
		Remediation: "Disable and stop the Print Spooler service on all Domain Controllers via GPO.",
		MITRE:       []string{"T1547.012", "T1068"}},

	{ID: "DC003", Name: "SMB signing not required on DC", Category: CategoryDomainControllers, Severity: SeverityHigh,
		Description: "SMB signing is not required on Domain Controllers, enabling SMB relay attacks.",
		Remediation: "Enable and require SMB signing via GPO on all Domain Controllers.",
		MITRE:       []string{"T1557.001"}},

	{ID: "DC004", Name: "LDAP signing not required", Category: CategoryDomainControllers, Severity: SeverityHigh,
		Description: "LDAP signing is not enforced on Domain Controllers, enabling LDAP relay attacks.",
		Remediation: "Set Domain Controller: LDAP server signing requirements to 'Require signing' via GPO.",
		MITRE:       []string{"T1557"}},

	{ID: "DC005", Name: "Domain functional level below 2016", Category: CategoryADStructure, Severity: SeverityMedium,
		Description: "The domain functional level is below Windows Server 2016, missing security features like Protected Users group improvements and Kerberos compound authentication.",
		Remediation: "Raise domain and forest functional level to Windows Server 2016 or higher.",
		MITRE:       []string{}},

	// AD Structure
	{ID: "S001", Name: "Tombstone lifetime too short", Category: CategoryADStructure, Severity: SeverityLow,
		Description: "The tombstone lifetime is less than 180 days, which can interfere with replication health and forensic investigations.",
		Remediation: "Set tombstone lifetime to at least 180 days.",
		MITRE:       []string{}},

	{ID: "S002", Name: "Protected Users group is empty", Category: CategoryADStructure, Severity: SeverityMedium,
		Description: "The Protected Users security group is empty. Adding privileged accounts provides additional Kerberos protections.",
		Remediation: "Add all privileged accounts (Domain Admins, etc.) to the Protected Users group.",
		MITRE:       []string{"T1558"}},

	{ID: "S003", Name: "Trust without SID filtering", Category: CategoryTrusts, Severity: SeverityHigh,
		Description: "An AD trust exists without SID filtering enabled. This allows SID history abuse across the trust.",
		Remediation: "Enable SID filtering on all external trusts: netdom trust <domain> /domain:<target> /quarantine:yes",
		MITRE:       []string{"T1134.005"}},

	{ID: "S004", Name: "LAPS not deployed on workstations", Category: CategoryADStructure, Severity: SeverityMedium,
		Description: "Local Administrator Password Solution (LAPS) is not deployed. Without LAPS, local admin passwords may be shared across machines enabling lateral movement.",
		Remediation: "Deploy Microsoft LAPS or Windows LAPS to manage unique local admin passwords on all machines.",
		MITRE:       []string{"T1078.003"}},
}
