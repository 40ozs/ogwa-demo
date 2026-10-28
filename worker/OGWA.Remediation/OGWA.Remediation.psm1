#Requires -Version 5.1
<#
    OGWA.Remediation - the remediation worker of OGWA, dry-run only (P10).

    Each state-changing command names one explicit target (stable identifiers plus the
    identity OGWA expects, never a pattern), declares SupportsShouldProcess with
    ConfirmImpact = 'High', and returns one structured result whose outcome is WhatIf,
    ValidationOnly, Simulated or Blocked. Every result states executed = $false and
    productionMutation = $false.

    There is no production adapter. The only adapter is the in-memory synthetic one made by
    New-OgwaSyntheticRemediationAdapter: it is data, never code, and the commands accept it
    only if it carries this module's private token. Anything else is Blocked
    (NO_PRODUCTION_ADAPTER) before any change is considered. A change is applied only to the
    synthetic adapter's in-memory world, and only when ShouldProcess agrees.

    The JSON boundary (Invoke-OgwaRemediation) accepts only the modes WhatIf and
    ValidateOnly, so a request document can never ask for a change. The contract is
    contract.json and docs/architecture/remediation.md.
#>
Set-StrictMode -Version 3.0

$script:Contract = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'contract.json') -Raw -Encoding UTF8 | ConvertFrom-Json
# Proves an adapter was made by this module. Not exported; a hashtable cannot forge it.
$script:SyntheticAdapterToken = New-Object -TypeName System.Object

foreach ($folder in 'Private', 'Public') {
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' | Sort-Object Name)) {
        . $file.FullName
    }
}

Export-ModuleMember -Function @(
    'Invoke-OgwaRemediation',
    'Move-OgwaADGroupToQuarantine',
    'New-OgwaSyntheticRemediationAdapter',
    'Remove-OgwaADGroup',
    'Remove-OgwaOktaGroupAssignment'
)
