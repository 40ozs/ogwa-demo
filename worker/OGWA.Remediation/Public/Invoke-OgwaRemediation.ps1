function Invoke-OgwaRemediation {
    <#
    .SYNOPSIS
        Process boundary of the remediation worker: request JSON in, result JSON out.

    .DESCRIPTION
        Parses one ogwa.remediation.request/v1 document, runs the one command its operation
        names against its one explicit target, and writes one ogwa.remediation.result/v1
        document. The request's mode is WhatIf or ValidateOnly; there is no mode that
        changes anything, and the command is always called with -WhatIf as well. A malformed
        request still produces a result (Blocked, INVALID_REQUEST).

        Without -Adapter every request is Blocked (NO_PRODUCTION_ADAPTER): this build has no
        production adapter.

    .EXAMPLE
        Invoke-OgwaRemediation -RequestPath .\request.json
    #>
    [CmdletBinding(DefaultParameterSetName = 'Json')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Json')][AllowEmptyString()][string]$RequestJson,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$RequestPath,
        [AllowNull()][object]$Adapter,
        [datetime]$ObservedAt = [datetime]::UtcNow
    )

    $maxRequestCharacters = 65536
    $request = $null
    $problem = $null
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $RequestJson = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 -ErrorAction Stop
        }
        if ($RequestJson.Length -gt $maxRequestCharacters) { $problem = "the request is larger than $maxRequestCharacters characters" }
        else { $request = ConvertFrom-Json -InputObject $RequestJson -ErrorAction Stop }
    }
    catch {
        $problem = 'the request could not be read as JSON'
    }

    $operation = $null
    $mode = $null
    $correlationId = $null
    $values = $null
    if (-not $problem) {
        $problem = Get-OgwaRequestProblem -Request $request
    }
    if (-not $problem) {
        $operation = $request.operation
        $mode = $request.mode
        $correlationId = $request.correlationId
        $values = [ordered]@{}
        foreach ($key in @($script:Contract.operations.$operation)) { $values[$key] = $request.target.$key }
    }
    if ($problem) {
        $known = if ($null -ne $request -and $request -isnot [string] -and $request.PSObject.Properties['operation'] -and
            @($script:Contract.operations.PSObject.Properties.Name) -ccontains $request.operation) { $request.operation } else { $null }
        $result = New-OgwaRemediationResult -Operation $known -CorrelationId $null -ObservedAt $ObservedAt
        Stop-OgwaRemediation -Result $result -Code 'REQUEST_VALID' -Reason 'INVALID_REQUEST' -Detail $problem
        return ConvertTo-Json -InputObject (Complete-OgwaRemediation -Result $result) -Depth 16
    }

    # Every call carries -WhatIf: ShouldProcess can never agree to a change from here.
    $common = @{ Adapter = $Adapter; CorrelationId = $correlationId; ObservedAt = $ObservedAt; WhatIf = $true }
    if ($mode -ceq 'ValidateOnly') { $common.ValidateOnly = $true }
    $output = switch -CaseSensitive ($operation) {
        'OKTA_GROUP_UNASSIGN' {
            Remove-OgwaOktaGroupAssignment @common -OktaAppId $values.oktaAppId -OktaGroupId $values.oktaGroupId
        }
        'AD_GROUP_QUARANTINE' {
            Move-OgwaADGroupToQuarantine @common -ObjectGuid $values.objectGuid -Domain $values.domain `
                -ExpectedSid $values.expectedSid -ExpectedDistinguishedName $values.expectedDistinguishedName `
                -QuarantineOu $values.quarantineOu
        }
        'AD_GROUP_DELETE' {
            Remove-OgwaADGroup @common -ObjectGuid $values.objectGuid -Domain $values.domain `
                -ExpectedSid $values.expectedSid -ExpectedDistinguishedName $values.expectedDistinguishedName
        }
    }
    ConvertTo-Json -InputObject $output -Depth 16
}
