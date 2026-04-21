<#
.SYNOPSIS
    Enumerates all GPOs with security settings and link information.
    Requires GroupPolicy module or RSAT.
#>
param([string]$Domain = $env:USERDNSDOMAIN)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

function Get-AllGPOs {
    param([string]$Domain)

    $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
    $gpoContainer = "CN=Policies,CN=System,$domainDN"
    $root     = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$gpoContainer")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)

    $searcher.Filter   = "(objectClass=groupPolicyContainer)"
    $searcher.PageSize = 500
    $searcher.PropertiesToLoad.AddRange(@(
        "distinguishedName","displayName","name","gPCFileSysPath",
        "versionNumber","flags","whenCreated","whenChanged","nTSecurityDescriptor"
    ))

    $results = $searcher.FindAll()
    $gpos    = [System.Collections.ArrayList]::new()

    # Get all OU GPO links
    $ouLinks = Get-AllOUGPOLinks -DomainDN $domainDN

    foreach ($result in $results) {
        $p = $result.Properties

        $guid = if ($p["name"].Count -gt 0) { $p["name"][0].ToString() } else { "" }
        $displayName = if ($p["displayname"].Count -gt 0) { $p["displayname"][0].ToString() } else { "" }
        $dn   = if ($p["distinguishedname"].Count -gt 0) { $p["distinguishedname"][0].ToString() } else { "" }
        $sysPath = if ($p["gpcfilesyspath"].Count -gt 0) { $p["gpcfilesyspath"][0].ToString() } else { "" }
        $flags = if ($p["flags"].Count -gt 0) { [int]$p["flags"][0] } else { 0 }
        $versionNum = if ($p["versionnumber"].Count -gt 0) { [int]$p["versionnumber"][0] } else { 0 }

        # Status: 0=All Enabled, 1=User Disabled, 2=Computer Disabled, 3=All Disabled
        $status = switch ($flags) {
            0 { "AllSettingsEnabled" }
            1 { "UserSettingsDisabled" }
            2 { "ComputerSettingsDisabled" }
            3 { "AllSettingsDisabled" }
            default { "Unknown" }
        }

        # Find links for this GPO
        $linkedOUs = @()
        $isLinked   = $false
        foreach ($link in $ouLinks) {
            if ($link.GPOGuid -eq $guid) {
                $linkedOUs += @{
                    ou_dn    = $link.OUDN
                    enabled  = $link.Enabled
                    enforced = $link.Enforced
                }
                $isLinked = $true
            }
        }

        # Try to read security settings from GPO SYSVOL path
        $pwdPolicy  = $null
        $lockPolicy = $null
        $secSettings = $null
        $sysvolWritable = $false

        if ($sysPath) {
            $iniPath  = "$sysPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            $xmlPath  = "$sysPath\MACHINE\Preferences\Registry\Registry.xml"

            if (Test-Path $iniPath) {
                $parsed = Parse-SecurityTemplate -Path $iniPath
                $pwdPolicy  = $parsed.PasswordPolicy
                $lockPolicy = $parsed.LockoutPolicy
                $secSettings = $parsed.SecurityOptions
            }

            # Check SYSVOL writable by non-admins
            $sysvolWritable = Test-SYSVOLWritable -Path $sysPath
        }

        $computerVersion = $versionNum -band 0xFFFF
        $userVersion     = ($versionNum -shr 16) -band 0xFFFF

        $gpo = @{
            id               = $guid
            name             = $displayName
            domain           = $Domain
            display_name     = $displayName
            status           = $status
            created          = if ($p["whencreated"].Count -gt 0) { $p["whencreated"][0].ToString("o") } else { $null }
            modified         = if ($p["whenchanged"].Count -gt 0) { $p["whenchanged"][0].ToString("o") } else { $null }
            linked_ous       = $linkedOUs
            is_linked        = $isLinked
            computer_version = $computerVersion
            user_version     = $userVersion
            password_policy  = $pwdPolicy
            account_lockout  = $lockPolicy
            security_settings = $secSettings
            sysvol_writable_by_nonadmin = $sysvolWritable
            permissions      = @()
        }
        $null = $gpos.Add($gpo)
    }

    $results.Dispose()
    return $gpos
}

function Get-AllOUGPOLinks {
    param([string]$DomainDN)

    $links  = @()
    $root   = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
    $srch   = New-Object System.DirectoryServices.DirectorySearcher($root)
    $srch.Filter   = "(|(objectClass=organizationalUnit)(objectClass=domain))"
    $srch.PageSize = 500
    $srch.PropertiesToLoad.Add("distinguishedName") | Out-Null
    $srch.PropertiesToLoad.Add("gPLink") | Out-Null

    $ous = $srch.FindAll()
    foreach ($ou in $ous) {
        $gpLink = if ($ou.Properties["gplink"].Count -gt 0) { $ou.Properties["gplink"][0].ToString() } else { "" }
        if (-not $gpLink) { continue }

        $ouDN = $ou.Properties["distinguishedname"][0].ToString()
        # gpLink format: [LDAP://cn={GUID},cn=policies,...;flags]
        $linkMatches = [regex]::Matches($gpLink, '\[LDAP://[^;]+;(\d+)\]')
        foreach ($match in $linkMatches) {
            $guidMatch = [regex]::Match($match.Value, '\{([A-Za-z0-9\-]+)\}')
            $flagVal   = [int]$match.Groups[1].Value
            if ($guidMatch.Success) {
                $links += @{
                    OUDN     = $ouDN
                    GPOGuid  = "{$($guidMatch.Groups[1].Value.ToUpper())}"
                    Enabled  = ($flagVal -band 1) -eq 0   # flag 1 = disabled
                    Enforced = ($flagVal -band 2) -ne 0   # flag 2 = enforced
                }
            }
        }
    }
    $ous.Dispose()
    return $links
}

function Parse-SecurityTemplate {
    param([string]$Path)
    $result = @{
        PasswordPolicy  = $null
        LockoutPolicy   = $null
        SecurityOptions = $null
    }
    try {
        $content  = Get-Content $Path -ErrorAction Stop
        $section  = ""
        $pwdData  = @{}
        $lockData = @{}
        $secData  = @{}

        foreach ($line in $content) {
            if ($line -match "^\[(.+)\]") {
                $section = $matches[1].Trim()
                continue
            }
            if ($line -match "^(.+)\s*=\s*(.+)$") {
                $key = $matches[1].Trim()
                $val = $matches[2].Trim()
                switch ($section) {
                    "System Access" {
                        switch ($key) {
                            "MinimumPasswordLength" { $pwdData.min_password_length = [int]$val }
                            "PasswordHistorySize"   { $pwdData.password_history_count = [int]$val }
                            "MaximumPasswordAge"    { $pwdData.max_password_age = [long]$val }
                            "MinimumPasswordAge"    { $pwdData.min_password_age = [long]$val }
                            "PasswordComplexity"    { $pwdData.complexity_enabled = ($val -eq "1") }
                            "ClearTextPassword"     { $pwdData.reversible_encryption = ($val -eq "1") }
                            "LockoutBadCount"       { $lockData.lockout_threshold = [int]$val }
                            "LockoutDuration"       { $lockData.lockout_duration = [long]$val }
                            "ResetLockoutCount"     { $lockData.observation_window = [long]$val }
                        }
                    }
                    "Registry Values" {
                        # WDigest
                        if ($key -match "UseLogonCredential") { $secData.wdigest_authentication = ($val -match "1$") }
                        # NTLMLv2
                        if ($key -match "LMCompatibilityLevel") { $secData.lm_authentication_level = [int]($val -replace '"','') }
                    }
                }
            }
        }

        if ($pwdData.Count -gt 0)  { $result.PasswordPolicy  = $pwdData }
        if ($lockData.Count -gt 0) { $result.LockoutPolicy   = $lockData }
        if ($secData.Count -gt 0)  { $result.SecurityOptions = $secData }
    } catch {}
    return $result
}

function Test-SYSVOLWritable {
    param([string]$Path)
    try {
        $acl = Get-Acl $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            $identity = $ace.IdentityReference.ToString().ToLower()
            $rights   = $ace.FileSystemRights.ToString().ToLower()
            # Flag if non-admin groups have write access
            if ($ace.AccessControlType -eq "Allow" -and
                ($rights -match "write|modify|fullcontrol") -and
                $identity -notmatch "administrator|system|domain admins|group policy") {
                return $true
            }
        }
    } catch {}
    return $false
}

$output = @{ gpos = @(); total = 0; error = $null }
try {
    $output.gpos  = Get-AllGPOs -Domain $Domain
    $output.total = $output.gpos.Count
} catch {
    $output.error = $_.ToString()
}

$output | ConvertTo-Json -Depth 10 -Compress
