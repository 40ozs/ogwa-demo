@{
    RootModule        = 'OGWA.Remediation.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '3c9e5a71-8d24-4f0b-a6e3-7b1d2c4f9e08'
    Author            = 'OGWA'
    Description       = 'OGWA remediation worker, dry-run only. Validates one explicit target, re-verifies its identity and protection, and answers WhatIf, ValidationOnly, Simulated (synthetic adapter only) or Blocked as structured results. It has no production adapter and never changes Okta or Active Directory.'
    PowerShellVersion = '5.1'

    # No ActiveDirectory or Okta module: the only adapter is the in-memory synthetic one.
    RequiredModules   = @()

    FunctionsToExport = @(
        'Invoke-OgwaRemediation',
        'Move-OgwaADGroupToQuarantine',
        'New-OgwaSyntheticRemediationAdapter',
        'Remove-OgwaADGroup',
        'Remove-OgwaOktaGroupAssignment'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags = @('Remediation', 'DryRun', 'WhatIf', 'Governance')
        }
    }
}
