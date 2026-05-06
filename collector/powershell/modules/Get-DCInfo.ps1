<#
.SYNOPSIS
    Collects Domain Controller security configuration details.
#>
param([string]$Domain = $env:USERDNSDOMAIN)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

function Get-DomainControllerInfo {
    param([string]$Domain)

    $domCtx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
    $dom    = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domCtx)

    $dcInfoList = [System.Collections.ArrayList]::new()

    foreach ($dc in $dom.DomainControllers) {
        $dcInfo = @{
            name              = $dc.Name.Split(".")[0]
            host_name         = $dc.Name
            ip_address        = ""
            site              = $dc.SiteName
            domain            = $Domain
            forest            = $dc.Forest.Name
            operating_system  = $dc.OSVersion
            os_version        = $dc.OSVersion
            is_read_only      = $false
            is_global_catalog = $dc.IsGlobalCatalog()
            fsmo_roles        = @()
            spooler_running   = $false
            wdigest_enabled   = $false
            smb_signing_enabled   = $false
            smb_signing_required  = $false
            ldap_signing_required = $false
            ntlm_restricted   = $false
            last_replication  = $null
            replication_errors = 0
            replication_partners = @()
            last_logon        = $null
        }

        # FSMO roles
        $fsmoRoles = @()
        try {
            if ($dom.PdcRoleOwner.Name -eq $dc.Name)             { $fsmoRoles += "PDC Emulator" }
            if ($dom.RidRoleOwner.Name -eq $dc.Name)             { $fsmoRoles += "RID Master" }
            if ($dom.InfrastructureRoleOwner.Name -eq $dc.Name)  { $fsmoRoles += "Infrastructure Master" }
        } catch {}
        try {
            $forest = $dc.Forest
            if ($forest.SchemaRoleOwner.Name -eq $dc.Name)   { $fsmoRoles += "Schema Master" }
            if ($forest.NamingRoleOwner.Name -eq $dc.Name)   { $fsmoRoles += "Domain Naming Master" }
        } catch {}
        $dcInfo.fsmo_roles = $fsmoRoles

        # Try to get IP
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($dc.Name) | Where-Object { $_.AddressFamily -eq "InterNetwork" }
            if ($ips) { $dcInfo.ip_address = $ips[0].ToString() }
        } catch {}

        # Check if RODC (Read-Only DC)
        try {
            $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")
            $rodc     = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=$($dc.Name.Split(".")[0]),OU=Domain Controllers,$domainDN")
            $pgid     = $rodc.Properties["primaryGroupID"]
            if ($pgid -and $pgid[0] -eq 521) {
                $dcInfo.is_read_only = $true
            }
        } catch {}

        # Remote checks (requires network access to each DC)
        try {
            # Check Print Spooler
            $spooler = Get-Service -ComputerName $dc.Name -Name "Spooler" -ErrorAction SilentlyContinue
            $dcInfo.spooler_running = ($spooler -and $spooler.Status -eq "Running")
        } catch { $dcInfo.spooler_running = $false }

        try {
            # Check SMB signing via registry
            $smbReg = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                $params = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue
                @{
                    EnableSecuritySignature  = $params.EnableSecuritySignature
                    RequireSecuritySignature = $params.RequireSecuritySignature
                }
            } -ErrorAction SilentlyContinue

            if ($smbReg) {
                $dcInfo.smb_signing_enabled  = $smbReg.EnableSecuritySignature -eq 1
                $dcInfo.smb_signing_required = $smbReg.RequireSecuritySignature -eq 1
            }
        } catch {}

        try {
            # Check LDAP signing requirement
            $ldapReg = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue)."LDAPServerIntegrity"
                @{ LDAPServerIntegrity = $val }
            } -ErrorAction SilentlyContinue
            if ($ldapReg) {
                $dcInfo.ldap_signing_required = ($ldapReg.LDAPServerIntegrity -ge 2)
            }
        } catch {}

        try {
            # Check WDigest
            $wdigestReg = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential
                @{ UseLogonCredential = $val }
            } -ErrorAction SilentlyContinue
            if ($wdigestReg) {
                $dcInfo.wdigest_enabled = ($wdigestReg.UseLogonCredential -eq 1)
            }
        } catch {}

        # Replication status
        try {
            $replSummary = repadmin /showrepl $dc.Name /csv 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue
            if ($replSummary) {
                $errors = ($replSummary | Where-Object { $_."Number of Failures" -gt 0 }).Count
                $dcInfo.replication_errors   = $errors
                $lastRepl = $replSummary | Sort-Object "Last Success Time" -Descending | Select-Object -First 1
                if ($lastRepl) {
                    $dcInfo.last_replication = $lastRepl."Last Success Time"
                    $dcInfo.replication_partners = @($replSummary."Source DSA" | Select-Object -Unique)
                }
            }
        } catch {}

        $null = $dcInfoList.Add($dcInfo)
    }

    return $dcInfoList
}

$output = @{ domain_controllers = @(); total = 0; error = $null }
try {
    $output.domain_controllers = Get-DomainControllerInfo -Domain $Domain
    $output.total = $output.domain_controllers.Count
} catch {
    $output.error = $_.ToString()
}

$output | ConvertTo-Json -Depth 8 -Compress
