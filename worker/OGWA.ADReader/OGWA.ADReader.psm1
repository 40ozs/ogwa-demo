#Requires -Version 5.1
<#
    OGWA.ADReader - the read-only Active Directory boundary of OGWA.

    Every directory call goes through a "directory accessor": a hashtable of read
    operations (see New-OgwaADDirectory). The default accessor uses only Get-* cmdlets of
    the ActiveDirectory module. Tests inject a synthetic accessor instead.

    PowerShell objects are used internally; JSON appears only at the process boundary
    (Invoke-OgwaADReader). The report contract is docs/architecture/ad-integration.md.
#>
Set-StrictMode -Version 3.0

$script:Contract = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'contract.json') -Raw -Encoding UTF8 | ConvertFrom-Json

foreach ($folder in 'Private', 'Public') {
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' | Sort-Object Name)) {
        . $file.FullName
    }
}

Export-ModuleMember -Function @(
    'Get-OgwaADGroupReport',
    'Invoke-OgwaADReader',
    'New-OgwaADDirectory'
)
