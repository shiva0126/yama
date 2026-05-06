param(
    [string]$VBoxManage = 'D:\Program Files\Oracle\VirtualBox\VBoxManage.exe',
    [string]$BaseFolder = 'C:\Users\SHETTY\VirtualBox VMs'
)

$ErrorActionPreference = 'Stop'

function Invoke-VBox {
    param([Parameter(Mandatory)][string[]]$Args)
    & $VBoxManage @Args
    if ($LASTEXITCODE -ne 0) {
        throw "VBoxManage failed: $($Args -join ' ')"
    }
}

function Get-RegisteredVMs {
    $raw = & $VBoxManage list vms
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to list VirtualBox VMs'
    }
    return ($raw | ForEach-Object {
        if ($_ -match '^"([^"]+)"\s+\{') { $matches[1] }
    })
}

function Ensure-Clone {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Name
    )

    $registered = Get-RegisteredVMs
    if ($registered -contains $Name) {
        Write-Host "VM already exists: $Name"
        return
    }

    Write-Host "Cloning $Source -> $Name"
    Invoke-VBox -Args @(
        'clonevm', $Source,
        '--name', $Name,
        '--basefolder', $BaseFolder,
        '--mode', 'all',
        '--register'
    )
}

Write-Host 'Configuring LAB-DC01 networking...'
Invoke-VBox -Args @(
    'modifyvm', 'LAB-DC01',
    '--nic1', 'intnet',
    '--intnet1', 'ad-lab-net',
    '--nic2', 'nat',
    '--nat-pf2', 'rdp,tcp,,53389,,3389',
    '--nat-pf2', 'winrm,tcp,,5985,,5985'
)

Ensure-Clone -Source 'LAB-DC01' -Name 'LAB-CHILDDC'
Ensure-Clone -Source 'LAB-DC01' -Name 'LAB-SRV01'

Write-Host 'Adjusting clone NAT forwarding...'
Invoke-VBox -Args @(
    'modifyvm', 'LAB-CHILDDC',
    '--nat-pf2=delete=rdp',
    '--nat-pf2=delete=winrm',
    '--nat-pf2', 'rdp,tcp,,53390,,3389',
    '--nat-pf2', 'winrm,tcp,,5986,,5985'
)

Invoke-VBox -Args @(
    'modifyvm', 'LAB-SRV01',
    '--nat-pf2=delete=rdp',
    '--nat-pf2=delete=winrm',
    '--nat-pf2', 'rdp,tcp,,53391,,3389',
    '--nat-pf2', 'winrm,tcp,,5987,,5985'
)

Write-Host ''
Write-Host 'Lab substrate ready.'
Write-Host 'Next steps inside the guests:'
Write-Host '  1. Promote LAB-DC01 into the root forest.'
Write-Host '  2. Promote LAB-CHILDDC as the child domain controller.'
Write-Host '  3. Join LAB-SRV01 and Win10-VictimClient to the forest.'
Write-Host '  4. Keep Kali-AttackClient off-domain.'
