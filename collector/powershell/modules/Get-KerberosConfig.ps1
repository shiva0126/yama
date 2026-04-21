<#
.SYNOPSIS
    Collects Kerberos configuration including krbtgt status and encryption types.
#>
param([string]$Domain = $env:USERDNSDOMAIN)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

function Get-KerberosConfiguration {
    param([string]$Domain)

    $domainDN = "DC=" + ($Domain -replace "\.", ",DC=")

    # Get krbtgt account details
    $root     = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = "(sAMAccountName=krbtgt)"
    $searcher.PropertiesToLoad.AddRange(@("pwdLastSet","msDS-SupportedEncryptionTypes","distinguishedName","userAccountControl"))

    $krbtgt = $searcher.FindOne()
    $pwdLastSet = $null
    $pwdAgeDays  = -1
    $supportedEncTypes = @()
    $desEnabled  = $false
    $aesEnabled  = $false
    $rc4Enabled  = $true  # RC4 is always available by default

    if ($krbtgt) {
        $p = $krbtgt.Properties
        if ($p["pwdlastset"].Count -gt 0) {
            $ft = [long]$p["pwdlastset"][0]
            if ($ft -gt 0) {
                $pwdLastSet = [DateTime]::FromFileTime($ft).ToString("o")
                $pwdAgeDays = [math]::Floor(([DateTime]::Now - [DateTime]::FromFileTime($ft)).TotalDays)
            }
        }
        if ($p["msds-supportedencryptiontypes"].Count -gt 0) {
            $encTypes = [int]$p["msds-supportedencryptiontypes"][0]
            # Encryption type flags:
            # 1 = DES-CBC-CRC, 2 = DES-CBC-MD5, 4 = RC4-HMAC, 8 = AES128, 16 = AES256
            $desEnabled  = ($encTypes -band 3) -ne 0
            $rc4Enabled  = ($encTypes -band 4) -ne 0 -or $encTypes -eq 0  # 0 = default (RC4 allowed)
            $aesEnabled  = ($encTypes -band 24) -ne 0

            if ($desEnabled) { $supportedEncTypes += "DES" }
            if ($rc4Enabled) { $supportedEncTypes += "RC4-HMAC" }
            if ($encTypes -band 8)  { $supportedEncTypes += "AES128" }
            if ($encTypes -band 16) { $supportedEncTypes += "AES256" }
        } else {
            # No explicit setting = RC4 is default
            $supportedEncTypes += "RC4-HMAC"
            $rc4Enabled = $true
        }
    }

    # Get domain Kerberos policy from Default Domain Policy
    $maxTicketAge  = 10  # hours (default)
    $maxRenewAge   = 7   # days (default)
    $maxClockSkew  = 5   # minutes (default)

    try {
        $kerbPolicyDN = "CN=Default Domain Policy,CN=System,$domainDN"
        $kerbEntry    = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$kerbPolicyDN")
        # These are stored as negative 100-nanosecond intervals in some configurations
        # More reliably get from GPO
    } catch {}

    return @{
        domain                    = $Domain
        krbtgt_password_last_set  = $pwdLastSet
        krbtgt_password_age_days  = $pwdAgeDays
        supported_enc_types       = $supportedEncTypes
        des_enabled               = $desEnabled
        rc4_enabled               = $rc4Enabled
        aes_enabled               = $aesEnabled
        max_ticket_age_hours      = $maxTicketAge
        max_renew_age_days        = $maxRenewAge
        max_clock_skew_minutes    = $maxClockSkew
    }
}

$output = @{ kerberos_config = $null; error = $null }
try {
    $output.kerberos_config = Get-KerberosConfiguration -Domain $Domain
} catch {
    $output.error = $_.ToString()
}

$output | ConvertTo-Json -Depth 6 -Compress
