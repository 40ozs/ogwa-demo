function Invoke-OgwaADReader {
    <#
    .SYNOPSIS
        Process boundary of the reader: request JSON in, report JSON out.

    .DESCRIPTION
        Parses an ogwa.ad.group-read-request/v1 document, runs Get-OgwaADGroupReport and
        writes one ogwa.ad.group-report/v1 JSON document to the pipeline. A malformed
        request still produces a report (resolution.status = InvalidRequest).

    .EXAMPLE
        Import-Module .\worker\OGWA.ADReader
        Invoke-OgwaADReader -RequestPath .\request.json
    #>
    [CmdletBinding(DefaultParameterSetName = 'Json')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Json')][AllowEmptyString()][string]$RequestJson,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$RequestPath,
        [hashtable]$Directory,
        [datetime]$ObservedAt = [datetime]::UtcNow
    )

    $maxRequestCharacters = 65536
    $problem = $null
    $request = $null
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $RequestJson = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 -ErrorAction Stop
        }
        if ($RequestJson.Length -gt $maxRequestCharacters) {
            $problem = "the request is larger than $maxRequestCharacters characters"
        }
        else {
            $request = ConvertFrom-Json -InputObject $RequestJson -ErrorAction Stop
        }
    }
    catch {
        $problem = 'the request could not be read as JSON: ' + (Get-OgwaErrorText $_)
    }

    if ($problem) {
        $report = New-OgwaReport -ObservedAt $ObservedAt
        $report.resolution.status = 'InvalidRequest'
        $report.resolution.error = Get-OgwaErrorText $problem
    }
    else {
        $parameters = @{ Request = $request; ObservedAt = $ObservedAt }
        if ($PSBoundParameters.ContainsKey('Directory')) { $parameters.Directory = $Directory }
        $report = Get-OgwaADGroupReport @parameters
    }
    ConvertTo-Json -InputObject $report -Depth 32
}
