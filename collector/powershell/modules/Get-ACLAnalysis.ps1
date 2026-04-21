<#
.SYNOPSIS
    Analyzes ACLs on high-value AD objects for dangerous permissions.
    Checks: domain root, AdminSDHolder, privileged groups, krbtgt, DCs.
#>
param([string]$Domain = $env:USERDNSDOMAIN)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# Dangerous rights that enable privilege escalation
$DANGEROUS_RIGHTS = @{
    "GenericAll"        = "Full control - enables complete object takeover"
    "WriteDACL"         = "Can modify permissions, leading to full control"
    "WriteOwner"        = "Can take ownership, leading to full control"
    "GenericWrite"      = "Can modify most object attributes"
    "AllExtendedRights" = "All extended rights including DCSync and password reset"
    "ExtendedRight"     = "Extended right - check specific GUID"
}

# DCSync extended right GUIDs
$DCSYNC_GUIDS = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c"   # DS-Replication-Get-Changes-In-Filtered-Set
)

# Legitimate high-privilege principals (by SID suffix or name)
$LEGITIMATE_PRINCIPALS = @(
    "S-1-5-32-544",   # Administrators
    "-512",           # Domain Admins
    "-519",           # Enterprise Admins
    "-516",           # Domain Controllers
    "S-1-5-18",       # SYSTEM
    "S-1-5-9",        # Enterprise Domain Controllers
    "SYSTEM", "Domain Admins", "Enterprise Admins", "Administrators"
)

function Get-HighValueObjectACLs {
    param([string]$Domain)

    $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
    $aclList  = [System.Collections.ArrayList]::new()

    # High-value objects to check
    $targets = @(
        @{ DN = $domainDN;                                           Type = "Domain Root" },
        @{ DN = "CN=AdminSDHolder,CN=System,$domainDN";              Type = "AdminSDHolder" },
        @{ DN = "CN=Domain Admins,CN=Users,$domainDN";               Type = "Domain Admins Group" },
        @{ DN = "CN=Enterprise Admins,CN=Users,$domainDN";           Type = "Enterprise Admins Group" },
        @{ DN = "CN=Schema Admins,CN=Users,$domainDN";               Type = "Schema Admins Group" },
        @{ DN = "CN=Administrators,CN=Builtin,$domainDN";            Type = "Administrators Group" },
        @{ DN = "CN=krbtgt,CN=Users,$domainDN";                      Type = "krbtgt Account" },
        @{ DN = "OU=Domain Controllers,$domainDN";                   Type = "Domain Controllers OU" },
        @{ DN = "CN=Policies,CN=System,$domainDN";                   Type = "GPO Container" },
        @{ DN = "CN=Sites,CN=Configuration,$domainDN";               Type = "Sites Container" }
    )

    foreach ($target in $targets) {
        try {
            $acl = Get-ObjectACL -DN $target.DN -Domain $Domain -ObjectType $target.Type
            if ($acl) {
                $null = $aclList.Add($acl)
            }
        } catch {
            # Object may not exist (e.g., Enterprise Admins not in child domain)
        }
    }

    return $aclList
}

function Get-ObjectACL {
    param(
        [string]$DN,
        [string]$Domain,
        [string]$ObjectType
    )

    $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DN")
    if (-not $entry.Name) { return $null }

    $acl     = $entry.ObjectSecurity
    $owner   = ""
    try { $owner = $acl.GetOwner([System.Security.Principal.NTAccount]).ToString() } catch {}

    $aclEntries = [System.Collections.ArrayList]::new()

    foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
        $trustee     = $ace.IdentityReference.ToString()
        $accessType  = $ace.AccessControlType.ToString()
        $rights      = $ace.ActiveDirectoryRights.ToString()
        $isInherited = $ace.IsInherited

        # Check if this ACE is dangerous
        $isDangerous  = $false
        $dangerReason = ""

        foreach ($dangerRight in $DANGEROUS_RIGHTS.Keys) {
            if ($rights -match $dangerRight) {
                # Skip if trustee is a legitimate principal
                $isLegitimate = $false
                foreach ($legit in $LEGITIMATE_PRINCIPALS) {
                    if ($trustee -match [regex]::Escape($legit)) {
                        $isLegitimate = $true
                        break
                    }
                }
                if (-not $isLegitimate -and $accessType -eq "Allow") {
                    $isDangerous  = $true
                    $dangerReason = $DANGEROUS_RIGHTS[$dangerRight]
                    break
                }
            }
        }

        # Get object type GUID if available
        $objectTypeGuid = ""
        try { $objectTypeGuid = $ace.ObjectType.ToString() } catch {}

        # Special check for DCSync extended rights
        if ($objectTypeGuid -and $DCSYNC_GUIDS -contains $objectTypeGuid.ToLower()) {
            $isLegitimate = $false
            foreach ($legit in $LEGITIMATE_PRINCIPALS) {
                if ($trustee -match [regex]::Escape($legit)) {
                    $isLegitimate = $true
                    break
                }
            }
            if (-not $isLegitimate -and $accessType -eq "Allow") {
                $isDangerous  = $true
                $dangerReason = "DCSync replication right - enables credential dump"
            }
        }

        # Only include dangerous ACEs or all ACEs for domain root
        if ($isDangerous -or $ObjectType -eq "Domain Root" -or $ObjectType -eq "AdminSDHolder") {
            $aclEntry = @{
                trustee          = $trustee
                trustee_sid      = Resolve-SID -AccountName $trustee
                access_type      = $accessType
                rights           = $rights
                inheritance_type = $ace.InheritanceType.ToString()
                object_type      = $objectTypeGuid
                is_inherited     = $isInherited
                is_dangerous     = $isDangerous
                danger_reason    = $dangerReason
            }
            $null = $aclEntries.Add($aclEntry)
        }
    }

    return @{
        object_dn   = $DN
        object_type = $ObjectType
        owner       = $owner
        entries     = $aclEntries
    }
}

function Resolve-SID {
    param([string]$AccountName)
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($AccountName)
        return $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).ToString()
    } catch { return "" }
}

$output = @{ acls = @(); total = 0; error = $null }
try {
    $output.acls  = Get-HighValueObjectACLs -Domain $Domain
    $output.total = $output.acls.Count
} catch {
    $output.error = $_.ToString()
}

$output | ConvertTo-Json -Depth 10 -Compress
