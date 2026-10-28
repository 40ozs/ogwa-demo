@{
    RootModule        = 'OGWA.ADReader.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '0a7d2c3e-5b1f-4e8a-9c6d-2f4b8e1a7c05'
    Author            = 'OGWA'
    Description       = 'Read-only Active Directory group reader for OGWA. Resolves one group by a stable identifier and reports identity, membership, nesting, primary-group references and protection facts as JSON. It never changes the directory.'
    PowerShellVersion = '5.1'

    # The ActiveDirectory module is loaded on demand by New-OgwaADDirectory, so the
    # contract, request validation and tests work on hosts without RSAT.
    RequiredModules   = @()

    FunctionsToExport = @(
        'Get-OgwaADGroupReport',
        'Invoke-OgwaADReader',
        'New-OgwaADDirectory'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'ReadOnly', 'Governance')
        }
    }
}
