<#
.SYNOPSIS
    Enumerates Fine-Grained Password Policies (PSOs) in Active Directory.
    Outputs JSON for the Yama AD Assessment tool.
#>
param(
    [string]$Domain = $env:USERDNSDOMAIN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $domainObj    = Get-ADDomain -Identity $Domain
    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $Domain

    $psos = Get-ADFineGrainedPasswordPolicy -Filter * -Server $Domain -Properties * |
        Select-Object `
            Name,
            Precedence,
            MinPasswordLength,
            MinPasswordAge,
            MaxPasswordAge,
            LockoutThreshold,
            LockoutDuration,
            LockoutObservationWindow,
            PasswordHistoryCount,
            ComplexityEnabled,
            ReversibleEncryptionEnabled,
            @{N='AppliesToCount'; E={
                ($_ | Get-ADFineGrainedPasswordPolicySubject | Measure-Object).Count
            }},
            @{N='AppliesTo'; E={
                $_ | Get-ADFineGrainedPasswordPolicySubject | Select-Object -ExpandProperty Name
            }},
            @{N='Risks'; E={
                $risks = @()
                if ($_.MinPasswordLength -lt 12)       { $risks += "Short min password ($($_.MinPasswordLength) chars)" }
                if (-not $_.ComplexityEnabled)          { $risks += 'Complexity disabled' }
                if ($_.ReversibleEncryptionEnabled)     { $risks += 'Reversible encryption enabled' }
                if ($_.LockoutThreshold -eq 0)          { $risks += 'No account lockout' }
                if ($_.MaxPasswordAge -gt [TimeSpan]::FromDays(90)) { $risks += 'Password max age > 90 days' }
                $risks
            }}

    $psoList = @($psos)

    # Default domain policy as baseline
    $defaultPolicy = @{
        min_password_length    = $domainPolicy.MinPasswordLength
        min_password_age       = $domainPolicy.MinPasswordAge.ToString()
        max_password_age       = $domainPolicy.MaxPasswordAge.ToString()
        lockout_threshold      = $domainPolicy.LockoutThreshold
        lockout_duration       = $domainPolicy.LockoutDuration.ToString()
        complexity_enabled     = $domainPolicy.ComplexityEnabled
        password_history_count = $domainPolicy.PasswordHistoryCount
    }

    $result = @{
        domain         = $Domain
        total_psos     = $psoList.Count
        default_policy = $defaultPolicy
        psos           = $psoList
        collected_at   = (Get-Date).ToUniversalTime().ToString('o')
    }

    $result | ConvertTo-Json -Depth 6
}
catch {
    @{ error = $_.Exception.Message; domain = $Domain } | ConvertTo-Json
}
