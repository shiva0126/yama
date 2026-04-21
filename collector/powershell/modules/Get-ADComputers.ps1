<#
.SYNOPSIS
    Enumerates AD computer accounts with delegation and LAPS status.
#>
param([string]$Domain = $env:USERDNSDOMAIN)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$UAC_ACCOUNTDISABLE          = 0x0002
$UAC_TRUSTED_FOR_DELEGATION  = 0x80000
$UAC_TRUSTED_TO_AUTH_DELEGATION = 0x1000000

function Get-AllComputers {
    param([string]$Domain)

    $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
    $root     = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)

    $searcher.Filter   = "(objectClass=computer)"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@(
        "distinguishedName","sAMAccountName","name","dNSHostName",
        "objectSid","operatingSystem","operatingSystemVersion","operatingSystemServicePack",
        "userAccountControl","lastLogon","lastLogonTimestamp","pwdLastSet",
        "whenCreated","whenChanged","memberOf","servicePrincipalName",
        "ms-Mcs-AdmPwd",              # LAPS password attribute (legacy)
        "msLAPS-Password",            # Windows LAPS
        "msLAPS-PasswordExpirationTime",
        "ms-Mcs-AdmPwdExpirationTime", # Legacy LAPS expiry
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity", # RBCD
        "userAccountControl",
        "primaryGroupID",
        "location"
    ))

    $results   = $searcher.FindAll()
    $computers = [System.Collections.ArrayList]::new()

    # Get list of DC names for is_domain_controller flag
    $dcNames = Get-DCNames -Domain $Domain

    foreach ($result in $results) {
        $p = $result.Properties

        $uac = 0
        if ($p["useraccountcontrol"].Count -gt 0) { $uac = [int]$p["useraccountcontrol"][0] }

        $enabled              = -not ($uac -band $UAC_ACCOUNTDISABLE)
        $trustedForDelegation = ($uac -band $UAC_TRUSTED_FOR_DELEGATION) -ne 0
        $trustedToAuth        = ($uac -band $UAC_TRUSTED_TO_AUTH_DELEGATION) -ne 0

        $objectSid = ""
        if ($p["objectsid"].Count -gt 0) {
            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($p["objectsid"][0], 0)
                $objectSid = $sid.ToString()
            } catch {}
        }

        $name    = if ($p["name"].Count -gt 0) { $p["name"][0].ToString() } else { "" }
        $dns     = if ($p["dnshostname"].Count -gt 0) { $p["dnshostname"][0].ToString() } else { "" }
        $isDC    = $dcNames -contains $name -or ($p["distinguishedname"][0].ToString() -match "OU=Domain Controllers")
        $isRODC  = ($p["primarygroupid"].Count -gt 0) -and ([int]$p["primarygroupid"][0] -eq 521)

        # LAPS detection
        $lapsEnabled = $false
        $lapsExpiry  = $null
        if ($p["ms-mcs-admpwdexpirationtime"].Count -gt 0 -or $p["ms-mcs-admpwd"].Count -gt 0) {
            $lapsEnabled = $true
            if ($p["ms-mcs-admpwdexpirationtime"].Count -gt 0) {
                try { $lapsExpiry = [DateTime]::FromFileTime([long]$p["ms-mcs-admpwdexpirationtime"][0]).ToString("o") } catch {}
            }
        }
        if ($p["mslaps-password"].Count -gt 0 -or $p["mslaps-passwordexpirationtime"].Count -gt 0) {
            $lapsEnabled = $true
            if ($p["mslaps-passwordexpirationtime"].Count -gt 0) {
                try { $lapsExpiry = [DateTime]::FromFileTime([long]$p["mslaps-passwordexpirationtime"][0]).ToString("o") } catch {}
            }
        }

        $delegateTo = @($p["msds-allowedtodelegateto"] | ForEach-Object { $_.ToString() })

        $computer = @{
            distinguished_name             = if ($p["distinguishedname"].Count -gt 0) { $p["distinguishedname"][0].ToString() } else { "" }
            sam_account_name               = if ($p["samaccountname"].Count -gt 0) { $p["samaccountname"][0].ToString() } else { "" }
            name                           = $name
            dns_host_name                  = $dns
            domain                         = $Domain
            object_sid                     = $objectSid
            operating_system               = if ($p["operatingsystem"].Count -gt 0) { $p["operatingsystem"][0].ToString() } else { "" }
            operating_system_version       = if ($p["operatingsystemversion"].Count -gt 0) { $p["operatingsystemversion"][0].ToString() } else { "" }
            service_pack                   = if ($p["operatingsystemservicepack"].Count -gt 0) { $p["operatingsystemservicepack"][0].ToString() } else { "" }
            enabled                        = $enabled
            is_domain_controller           = $isDC
            is_read_only_dc                = $isRODC
            site                           = ""  # populated by topology module
            trusted_for_delegation         = $trustedForDelegation
            trusted_to_auth_for_delegation = $trustedToAuth
            allowed_to_delegate_to         = $delegateTo
            laps_enabled                   = $lapsEnabled
            laps_expiration                = $lapsExpiry
            created                        = if ($p["whencreated"].Count -gt 0) { $p["whencreated"][0].ToString("o") } else { $null }
            modified                       = if ($p["whenchanged"].Count -gt 0) { $p["whenchanged"][0].ToString("o") } else { $null }
            last_logon                     = ConvertFrom-FileTime (if ($p["lastlogon"].Count -gt 0) { [long]$p["lastlogon"][0] } else { 0 })
            last_logon_timestamp           = ConvertFrom-FileTime (if ($p["lastlogontimestamp"].Count -gt 0) { [long]$p["lastlogontimestamp"][0] } else { 0 })
            pwd_last_set                   = ConvertFrom-FileTime (if ($p["pwdlastset"].Count -gt 0) { [long]$p["pwdlastset"][0] } else { 0 })
            member_of                      = @($p["memberof"] | ForEach-Object { $_.ToString() })
            service_principal_names        = @($p["serviceprincipalname"] | ForEach-Object { $_.ToString() })
            user_account_control           = $uac
        }
        $null = $computers.Add($computer)
    }

    $results.Dispose()
    return $computers
}

function Get-DCNames {
    param([string]$Domain)
    try {
        $domCtx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
        $dom    = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domCtx)
        return @($dom.DomainControllers | ForEach-Object { $_.Name.Split(".")[0] })
    } catch { return @() }
}

function ConvertFrom-FileTime {
    param([long]$FileTime)
    if ($FileTime -le 0 -or $FileTime -eq [long]::MaxValue) { return $null }
    try { return [DateTime]::FromFileTime($FileTime).ToString("o") } catch { return $null }
}

$output = @{ computers = @(); total = 0; error = $null }
try {
    $output.computers = Get-AllComputers -Domain $Domain
    $output.total     = $output.computers.Count
} catch {
    $output.error = $_.ToString()
}

$output | ConvertTo-Json -Depth 8 -Compress
