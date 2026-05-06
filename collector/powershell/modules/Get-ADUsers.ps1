<#
.SYNOPSIS
    Enumerates all Active Directory users with security-relevant attributes.
    Outputs JSON for the AD Assessment tool.
#>
param(
    [string]$Domain = $env:USERDNSDOMAIN,
    [int]$StaleThresholdDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# UAC Flag constants
$UAC_ACCOUNTDISABLE          = 0x0002
$UAC_PASSWD_NOTREQD          = 0x0020
$UAC_PASSWD_CANT_CHANGE      = 0x0040
$UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
$UAC_NORMAL_ACCOUNT          = 0x0200
$UAC_DONT_EXPIRE_PASSWORD    = 0x10000
$UAC_SMARTCARD_REQUIRED      = 0x40000
$UAC_TRUSTED_FOR_DELEGATION  = 0x80000
$UAC_NOT_DELEGATED           = 0x100000
$UAC_USE_DES_KEY_ONLY        = 0x200000
$UAC_DONT_REQ_PREAUTH        = 0x400000
$UAC_TRUSTED_TO_AUTH_DELEGATION = 0x1000000

# Privileged group RID patterns
$PRIVILEGED_GROUP_RIDS = @("-512", "-518", "-519", "-544", "-548", "-549")

function Get-AllUsers {
    param([string]$Domain)

    $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
    $root     = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)

    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcher.PageSize = 1000
    $searcher.SearchScope = "Subtree"
    $searcher.PropertiesToLoad.AddRange(@(
        "distinguishedName", "sAMAccountName", "userPrincipalName",
        "displayName", "givenName", "sn", "mail", "department", "title",
        "description", "objectSid", "objectGuid",
        "userAccountControl", "adminCount",
        "whenCreated", "whenChanged",
        "lastLogon", "lastLogonTimestamp", "pwdLastSet", "accountExpires",
        "memberOf", "servicePrincipalName", "msDS-AllowedToDelegateTo",
        "msDS-GroupMSAMembership",     # gMSA indicator
        "objectClass"
    ))

    $results = $searcher.FindAll()
    $users   = [System.Collections.ArrayList]::new()

    foreach ($result in $results) {
        $p = $result.Properties

        $uac = 0
        if ($p["useraccountcontrol"].Count -gt 0) {
            $uac = [int]$p["useraccountcontrol"][0]
        }

        # Compute boolean flags from UAC
        $enabled                = -not ($uac -band $UAC_ACCOUNTDISABLE)
        $pwdNeverExpires        = ($uac -band $UAC_DONT_EXPIRE_PASSWORD) -ne 0
        $pwdNotRequired         = ($uac -band $UAC_PASSWD_NOTREQD) -ne 0
        $reversibleEncryption   = ($uac -band $UAC_ENCRYPTED_TEXT_PWD_ALLOWED) -ne 0
        $smartcardRequired      = ($uac -band $UAC_SMARTCARD_REQUIRED) -ne 0
        $trustedForDelegation   = ($uac -band $UAC_TRUSTED_FOR_DELEGATION) -ne 0
        $trustedToAuth          = ($uac -band $UAC_TRUSTED_TO_AUTH_DELEGATION) -ne 0
        $dontReqPreauth         = ($uac -band $UAC_DONT_REQ_PREAUTH) -ne 0
        $useDesKeyOnly          = ($uac -band $UAC_USE_DES_KEY_ONLY) -ne 0

        # Parse timestamps
        $lastLogon   = ConvertFrom-FileTime ($p["lastlogon"][0] ?? 0)
        $lastLogonTS = ConvertFrom-FileTime ($p["lastlogontimestamp"][0] ?? 0)
        $pwdLastSet  = ConvertFrom-FileTime ($p["pwdlastset"][0] ?? 0)
        $created     = if ($p["whencreated"].Count -gt 0) { $p["whencreated"][0] } else { $null }
        $modified    = if ($p["whenchanged"].Count -gt 0) { $p["whenchanged"][0] } else { $null }

        # SID
        $objectSid = ""
        if ($p["objectsid"].Count -gt 0) {
            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($p["objectsid"][0], 0)
                $objectSid = $sid.ToString()
            } catch {}
        }

        # Member of
        $memberOf = @($p["memberof"] | ForEach-Object { $_.ToString() })

        # SPNs
        $spns = @($p["serviceprincipalname"] | ForEach-Object { $_.ToString() })

        # Constrained delegation targets
        $delegateTo = @($p["msds-allowedtodelegateto"] | ForEach-Object { $_.ToString() })

        # Is MSA or gMSA
        $objectClasses = @($p["objectclass"] | ForEach-Object { $_.ToString().ToLower() })
        $isMSA  = $objectClasses -contains "msDS-ManagedServiceAccount".ToLower()
        $isGMSA = $objectClasses -contains "msDS-GroupManagedServiceAccount".ToLower()

        # Is service account heuristic
        $samName = if ($p["samaccountname"].Count -gt 0) { $p["samaccountname"][0].ToString() } else { "" }
        $isServiceAccount = $isMSA -or $isGMSA -or
            ($samName -match "^svc[_-]" ) -or
            ($samName -match "_svc$") -or
            ($samName -match "service" -and $spns.Count -gt 0)

        # AdminCount
        $adminCount = 0
        if ($p["admincount"].Count -gt 0) { $adminCount = [int]$p["admincount"][0] }

        # Privileged check
        $isPrivileged = $adminCount -eq 1
        $privilegedGroups = @()
        foreach ($groupDN in $memberOf) {
            foreach ($rid in $PRIVILEGED_GROUP_RIDS) {
                if ($groupDN -match $rid) {
                    $isPrivileged = $true
                    $cn = ($groupDN -split ",")[0] -replace "^CN=", ""
                    $privilegedGroups += $cn
                    break
                }
            }
        }

        $user = @{
            distinguished_name             = if ($p["distinguishedname"].Count -gt 0) { $p["distinguishedname"][0].ToString() } else { "" }
            sam_account_name               = $samName
            user_principal_name            = if ($p["userprincipalname"].Count -gt 0) { $p["userprincipalname"][0].ToString() } else { "" }
            display_name                   = if ($p["displayname"].Count -gt 0) { $p["displayname"][0].ToString() } else { "" }
            given_name                     = if ($p["givenname"].Count -gt 0) { $p["givenname"][0].ToString() } else { "" }
            surname                        = if ($p["sn"].Count -gt 0) { $p["sn"][0].ToString() } else { "" }
            email_address                  = if ($p["mail"].Count -gt 0) { $p["mail"][0].ToString() } else { "" }
            department                     = if ($p["department"].Count -gt 0) { $p["department"][0].ToString() } else { "" }
            title                          = if ($p["title"].Count -gt 0) { $p["title"][0].ToString() } else { "" }
            description                    = if ($p["description"].Count -gt 0) { $p["description"][0].ToString() } else { "" }
            domain                         = $Domain
            object_sid                     = $objectSid
            enabled                        = $enabled
            password_never_expires         = $pwdNeverExpires
            password_not_required          = $pwdNotRequired
            reversible_encryption          = $reversibleEncryption
            smartcard_required             = $smartcardRequired
            trusted_for_delegation         = $trustedForDelegation
            trusted_to_auth_for_delegation = $trustedToAuth
            dont_require_preauth           = $dontReqPreauth
            use_des_key_only               = $useDesKeyOnly
            admin_count                    = $adminCount
            is_privileged                  = $isPrivileged
            privileged_groups              = $privilegedGroups
            is_service_account             = $isServiceAccount
            is_msa                         = $isMSA
            is_gmsa                        = $isGMSA
            user_account_control           = $uac
            created                        = $(if ($created) { $created.ToString("o") } else { $null })
            modified                       = $(if ($modified) { $modified.ToString("o") } else { $null })
            last_logon                     = $lastLogon
            last_logon_timestamp           = $lastLogonTS
            pwd_last_set                   = $pwdLastSet
            member_of                      = $memberOf
            service_principal_names        = $spns
            allowed_to_delegate_to         = $delegateTo
        }
        $null = $users.Add($user)
    }

    $results.Dispose()
    return $users
}

function ConvertFrom-FileTime {
    param([long]$FileTime)
    if ($FileTime -le 0 -or $FileTime -eq [long]::MaxValue -or $FileTime -eq 9223372036854775807) {
        return $null
    }
    try {
        return [DateTime]::FromFileTime($FileTime).ToString("o")
    } catch {
        return $null
    }
}

# Main
$output = @{
    users = @()
    total = 0
    error = $null
}

try {
    $output.users = Get-AllUsers -Domain $Domain
    $output.total = $output.users.Count
} catch {
    $output.error = $_.ToString()
}

$output | ConvertTo-Json -Depth 8 -Compress
