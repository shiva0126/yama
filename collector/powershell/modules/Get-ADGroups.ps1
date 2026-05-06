<#
.SYNOPSIS
    Enumerates all AD groups with members, nesting, and privilege classification.
#>
param([string]$Domain = $env:USERDNSDOMAIN)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$PRIVILEGED_SIDS = @{
    "-512" = "Domain Admins"
    "-518" = "Schema Admins"
    "-519" = "Enterprise Admins"
    "-516" = "Domain Controllers"
    "-498" = "Enterprise Read-Only DCs"
    "-521" = "Read-Only Domain Controllers"
    "-526" = "Key Admins"
    "-527" = "Enterprise Key Admins"
}
$PRIVILEGED_NAMES = @(
    "Administrators","Account Operators","Server Operators","Print Operators",
    "Backup Operators","Replicators","Remote Management Users","Protected Users"
)

function Get-AllGroups {
    param([string]$Domain)

    $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
    $root     = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)

    $searcher.Filter    = "(objectClass=group)"
    $searcher.PageSize  = 1000
    $searcher.PropertiesToLoad.AddRange(@(
        "distinguishedName","sAMAccountName","name","description",
        "objectSid","groupType","adminCount","whenCreated","whenChanged",
        "member","memberOf"
    ))

    $results = $searcher.FindAll()
    $groups  = [System.Collections.ArrayList]::new()

    foreach ($result in $results) {
        $p = $result.Properties

        $objectSid = ""
        if ($p["objectsid"].Count -gt 0) {
            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($p["objectsid"][0], 0)
                $objectSid = $sid.ToString()
            } catch {}
        }

        $groupType = if ($p["grouptype"].Count -gt 0) { [int]$p["grouptype"][0] } else { 0 }
        # GroupType flags: -2147483646=Global Security, -2147483644=DomainLocal Security, -2147483640=Universal Security
        $scope    = Get-GroupScope -GroupType $groupType
        $category = Get-GroupCategory -GroupType $groupType

        $members     = @($p["member"]   | ForEach-Object { $_.ToString() })
        $memberOf    = @($p["memberof"] | ForEach-Object { $_.ToString() })
        $nestedGroups = @()

        # Find nested groups (members that are groups)
        foreach ($memberDN in $members) {
            if ($memberDN -match "^CN=.*,(?:CN=Users|CN=Builtin|OU=)" -or $memberDN -match "objectClass=group") {
                $nestedGroups += $memberDN
            }
        }

        $name     = if ($p["name"].Count -gt 0) { $p["name"][0].ToString() } else { "" }
        $adminCnt = if ($p["admincount"].Count -gt 0) { [int]$p["admincount"][0] } else { 0 }

        # Determine if privileged
        $isPrivileged   = $adminCnt -eq 1
        $privilegeLevel = "None"

        foreach ($rid in $PRIVILEGED_SIDS.Keys) {
            if ($objectSid.EndsWith($rid)) {
                $isPrivileged   = $true
                $privilegeLevel = "Tier0"
                break
            }
        }
        if (-not $isPrivileged) {
            foreach ($privName in $PRIVILEGED_NAMES) {
                if ($name -eq $privName) {
                    $isPrivileged   = $true
                    $privilegeLevel = "Tier0"
                    break
                }
            }
        }

        $group = @{
            distinguished_name = if ($p["distinguishedname"].Count -gt 0) { $p["distinguishedname"][0].ToString() } else { "" }
            sam_account_name   = if ($p["samaccountname"].Count -gt 0) { $p["samaccountname"][0].ToString() } else { "" }
            name               = $name
            description        = if ($p["description"].Count -gt 0) { $p["description"][0].ToString() } else { "" }
            domain             = $Domain
            object_sid         = $objectSid
            group_scope        = $scope
            group_category     = $category
            members            = $members
            member_of          = $memberOf
            nested_groups      = $nestedGroups
            admin_count        = $adminCnt
            is_privileged      = $isPrivileged
            privilege_level    = $privilegeLevel
            created            = if ($p["whencreated"].Count -gt 0) { $p["whencreated"][0].ToString("o") } else { $null }
            modified           = if ($p["whenchanged"].Count -gt 0) { $p["whenchanged"][0].ToString("o") } else { $null }
        }
        $null = $groups.Add($group)
    }

    $results.Dispose()
    return $groups
}

function Get-GroupScope {
    param([int]$GroupType)
    switch ($GroupType) {
        -2147483646 { return "Global" }
        -2147483644 { return "DomainLocal" }
        -2147483640 { return "Universal" }
        2           { return "Global" }
        4           { return "DomainLocal" }
        8           { return "Universal" }
        default     { return "Unknown" }
    }
}

function Get-GroupCategory {
    param([int]$GroupType)
    if ($GroupType -lt 0) { return "Security" }
    return "Distribution"
}

$output = @{ groups = @(); total = 0; error = $null }
try {
    $output.groups = Get-AllGroups -Domain $Domain
    $output.total  = $output.groups.Count
} catch {
    $output.error = $_.ToString()
}

$output | ConvertTo-Json -Depth 8 -Compress
