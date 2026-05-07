<#
.SYNOPSIS
    Enumerates Active Directory trust relationships for the target domain.
    Outputs JSON for the Yama AD Assessment tool.
#>
param(
    [string]$Domain = $env:USERDNSDOMAIN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $trusts = Get-ADTrust -Filter * -Server $Domain -Properties * |
        Select-Object `
            Name,
            Direction,
            TrustType,
            TrustAttributes,
            TrustDirection,
            Source,
            Target,
            IntraForest,
            IsTreeParent,
            IsTreeRoot,
            SIDFilteringQuarantined,
            SIDFilteringForestAware,
            SelectiveAuthentication,
            ForestTransitive,
            @{N='Direction_Label'; E={
                switch ($_.Direction) {
                    1 { 'Inbound (they trust us)' }
                    2 { 'Outbound (we trust them)' }
                    3 { 'Bidirectional' }
                    default { "Unknown ($($_.Direction))" }
                }
            }},
            @{N='Risks'; E={
                $risks = @()
                if (-not $_.SIDFilteringQuarantined) { $risks += 'SID Filtering disabled' }
                if ($_.ForestTransitive -and $_.Direction -in @(2,3)) { $risks += 'Forest-transitive outbound trust' }
                if ($_.TrustAttributes -band 0x40) { $risks += 'Cross-organisation trust' }
                $risks
            }}

    $trustList = @($trusts)

    # Risk summary
    $riskyTrusts = @($trustList | Where-Object { $_.Risks.Count -gt 0 })

    $result = @{
        domain        = $Domain
        total_trusts  = $trustList.Count
        risky_trusts  = $riskyTrusts.Count
        trusts        = $trustList
        collected_at  = (Get-Date).ToUniversalTime().ToString('o')
    }

    $result | ConvertTo-Json -Depth 6
}
catch {
    @{ error = $_.Exception.Message; domain = $Domain } | ConvertTo-Json
}
