<#
.SYNOPSIS
    Collects Active Directory forest and domain topology information.
    Outputs JSON for consumption by the AD Assessment collector agent.
#>
param(
    [string]$Domain = $env:USERDNSDOMAIN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ForestInfo {
    param([string]$Domain)

    try {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $rootDomain = $forest.RootDomain

        $forestData = @{
            name             = $forest.Name
            root_domain      = $rootDomain.Name
            functional_level = [int]$forest.ForestModeLevel
            schema_version   = Get-SchemaVersion
            global_catalogs  = @($forest.GlobalCatalogs | ForEach-Object { $_.Name })
            domains          = @()
            trusts           = @()
            sites            = @()
            collected_at     = (Get-Date -Format "o")
        }

        # Enumerate domains
        foreach ($dom in $forest.Domains) {
            $forestData.domains += Get-DomainInfo -DomainObj $dom
        }

        # Enumerate trusts
        foreach ($trust in $forest.GetAllTrustRelationships()) {
            $forestData.trusts += @{
                source_domain   = $trust.SourceName
                target_domain   = $trust.TargetName
                trust_type      = $trust.TrustType.ToString()
                trust_direction = $trust.TrustDirection.ToString()
                is_transitive   = $true
                sid_filtering   = $false  # populated below
                selective_auth  = $false
            }
        }

        # Enumerate sites
        foreach ($site in $forest.Sites) {
            $siteData = @{
                name    = $site.Name
                subnets = @($site.Subnets | ForEach-Object { $_.Name })
                dcs     = @($site.Servers | ForEach-Object { $_.Name })
            }
            $forestData.sites += $siteData
        }

        return $forestData
    }
    catch {
        Write-Error "Failed to get forest info: $_"
        return $null
    }
}

function Get-DomainInfo {
    param($DomainObj)

    try {
        $domainContext = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DomainObj.Name)")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainContext)
        $searcher.Filter = "(objectClass=domain)"
        $searcher.PropertiesToLoad.AddRange(@(
            "distinguishedName","name","dc","msDS-Behavior-Version",
            "maxPwdAge","minPwdAge","minPwdLength","pwdHistoryLength",
            "lockoutThreshold","lockoutDuration","tombstoneLifetime"
        ))
        $result = $searcher.FindOne()

        $domainDN = $result.Properties["distinguishedname"][0]
        $functionalLevel = 0
        if ($result.Properties["msds-behavior-version"].Count -gt 0) {
            $functionalLevel = [int]$result.Properties["msds-behavior-version"][0]
        }

        # Get FSMO roles
        $pdcEmulator  = ""
        $ridMaster    = ""
        $infraMaster  = ""
        try {
            $domAD = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(
                (New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $DomainObj.Name))
            )
            $pdcEmulator = $domAD.PdcRoleOwner.Name
            $ridMaster   = $domAD.RidRoleOwner.Name
            $infraMaster = $domAD.InfrastructureRoleOwner.Name
        } catch {}

        # Get password policy values (convert AD ticks to useful values)
        $maxPwdAge = 0
        $minPwdAge = 0
        if ($result.Properties["maxpwdage"].Count -gt 0) {
            $maxPwdAge = [math]::Abs([long]$result.Properties["maxpwdage"][0])
        }

        return @{
            distinguished_name    = $domainDN
            name                  = $DomainObj.Name
            netbios               = ($DomainObj.NetBiosName ?? "")
            forest                = $DomainObj.Forest.Name
            functional_level      = $functionalLevel
            domain_sid            = Get-DomainSID -DomainDN $domainDN
            pdc_emulator          = $pdcEmulator
            rid_master            = $ridMaster
            infrastructure_master = $infraMaster
            domain_controllers    = @($DomainObj.DomainControllers | ForEach-Object { $_.Name })
            child_domains         = @($DomainObj.Children | ForEach-Object { $_.Name })
            parent_domain         = ($DomainObj.Parent?.Name ?? "")
            tombstone_lifetime    = Get-TombstoneLifetime -DomainDN $domainDN
            max_pwd_age           = $maxPwdAge
            min_pwd_age           = $minPwdAge
            min_pwd_length        = $(if ($result.Properties["minpwdlength"].Count -gt 0) { [int]$result.Properties["minpwdlength"][0] } else { 0 })
            pwd_history_length    = $(if ($result.Properties["pwdhistorylength"].Count -gt 0) { [int]$result.Properties["pwdhistorylength"][0] } else { 0 })
            lockout_threshold     = $(if ($result.Properties["lockoutthreshold"].Count -gt 0) { [int]$result.Properties["lockoutthreshold"][0] } else { 0 })
        }
    }
    catch {
        return @{
            name  = $DomainObj.Name
            error = $_.ToString()
        }
    }
}

function Get-DomainSID {
    param([string]$DomainDN)
    try {
        $entry  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
        $sidBytes = $entry.Properties["objectSid"][0]
        $sid    = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
        return $sid.ToString()
    } catch { return "" }
}

function Get-TombstoneLifetime {
    param([string]$DomainDN)
    try {
        # Tombstone lifetime is in CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...
        $configDN = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + ($DomainDN -replace "^DC=", "DC=")
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$configDN")
        if ($entry.Properties["tombstoneLifetime"].Count -gt 0) {
            return [int]$entry.Properties["tombstoneLifetime"][0]
        }
        return 60 # default
    } catch { return 0 }
}

function Get-SchemaVersion {
    try {
        $schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema()
        $entry  = $schema.GetDirectoryEntry()
        if ($entry.Properties["objectVersion"].Count -gt 0) {
            return [int]$entry.Properties["objectVersion"][0]
        }
        return 0
    } catch { return 0 }
}

# Main execution
$result = @{
    forest  = $null
    domains = @()
    error   = $null
}

try {
    $result.forest  = Get-ForestInfo -Domain $Domain
    $result.domains = $result.forest.domains
}
catch {
    $result.error = $_.ToString()
}

$result | ConvertTo-Json -Depth 10 -Compress
