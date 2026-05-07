<#
.SYNOPSIS
    Enumerates Active Directory Organizational Units with delegation and GPO link info.
    Outputs JSON for the Yama AD Assessment tool.
#>
param(
    [string]$Domain = $env:USERDNSDOMAIN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $domainObj = Get-ADDomain -Identity $Domain
    $baseDN    = $domainObj.DistinguishedName

    $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $baseDN -Properties `
        Name, DistinguishedName, Description, ProtectedFromAccidentalDeletion,
        LinkedGroupPolicyObjects, ManagedBy, Created, Modified |
        Select-Object `
            Name,
            DistinguishedName,
            Description,
            ProtectedFromAccidentalDeletion,
            ManagedBy,
            @{N='GPOLinkCount'; E={ ($_.LinkedGroupPolicyObjects | Measure-Object).Count }},
            @{N='LinkedGPOs';   E={ $_.LinkedGroupPolicyObjects }},
            @{N='Created';      E={ $_.Created.ToString('o') }},
            @{N='Modified';     E={ $_.Modified.ToString('o') }},
            @{N='Path';         E={
                # Build friendly path by removing baseDN suffix
                $dn = $_.DistinguishedName
                if ($dn -eq $baseDN) { '(root)' }
                else { $dn.Replace(",$baseDN",'') }
            }}

    # Detect OUs with no GPOs applied (potential policy gaps)
    $ouList = @($ous) | ForEach-Object {
        $_ | Add-Member -NotePropertyName 'HasNoGPO' -NotePropertyValue ($_.GPOLinkCount -eq 0) -PassThru
    }

    $result = @{
        domain      = $Domain
        total_ous   = $ouList.Count
        ous         = $ouList
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
    }

    $result | ConvertTo-Json -Depth 6
}
catch {
    @{ error = $_.Exception.Message; domain = $Domain } | ConvertTo-Json
}
