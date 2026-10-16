# Request validation for the JSON boundary. Anything unexpected is refused before any lookup.

function Get-OgwaRequestProblem {
    # $null for a well-formed request; otherwise why not. Strict: unknown keys are refused.
    param([AllowNull()][object]$Request)

    if ($null -eq $Request -or $Request.GetType().FullName -ne 'System.Management.Automation.PSCustomObject') {
        return 'the request must be a JSON object'
    }
    $keys = @($Request.PSObject.Properties | ForEach-Object { $_.Name })
    $expected = @('schema', 'operation', 'mode', 'correlationId', 'target')
    if ($keys.Count -ne $expected.Count -or @($keys | Where-Object { $expected -cnotcontains $_ }).Count -gt 0) {
        return 'the request must have exactly: ' + ($expected -join ', ')
    }
    if ($Request.schema -cne $script:Contract.requestSchema) { return "schema must be '$($script:Contract.requestSchema)'" }
    $operations = @($script:Contract.operations.PSObject.Properties.Name)
    if (-not ($Request.operation -is [string]) -or $operations -cnotcontains $Request.operation) {
        return 'operation must be one of: ' + ($operations -join ', ')
    }
    if (-not ($Request.mode -is [string]) -or @($script:Contract.modes) -cnotcontains $Request.mode) {
        return 'mode must be one of: ' + (@($script:Contract.modes) -join ', ') + '; no mode changes anything'
    }
    if (-not ($Request.correlationId -is [string]) -or $Request.correlationId -cnotmatch $script:CorrelationPattern) {
        return 'correlationId must be 1-100 characters from [A-Za-z0-9._:-]'
    }
    $target = $Request.target
    if ($null -eq $target -or $target.GetType().FullName -ne 'System.Management.Automation.PSCustomObject') {
        return 'target must be one JSON object: a remediation names a single explicit target'
    }
    $targetKeys = @($target.PSObject.Properties | ForEach-Object { $_.Name })
    $allowed = @($script:Contract.operations.($Request.operation))
    if ($targetKeys.Count -ne $allowed.Count -or @($targetKeys | Where-Object { $allowed -cnotcontains $_ }).Count -gt 0) {
        return "target for $($Request.operation) must have exactly: " + ($allowed -join ', ')
    }
    foreach ($key in $allowed) {
        if (-not ($target.$key -is [string])) { return "target.$key must be a string" }
    }
    $null
}
