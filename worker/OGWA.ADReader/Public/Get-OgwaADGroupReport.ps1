function Get-OgwaADGroupReport {
    <#
    .SYNOPSIS
        Reads one AD group and returns a normalized, read-only report.

    .DESCRIPTION
        Resolves the group named by the request (preferably by objectGUID or objectSid) and,
        once exactly one match is proven, reads its identity, direct members, nested
        members, primary-group references, parent groups and protection facts.

        Never throws for directory problems: every outcome, including an invalid request or
        an unreachable domain, is a report whose resolution.status says what happened.
        Nothing in this function or its accessor changes the directory.

    .PARAMETER Request
        A request object (hashtable or parsed JSON) following ogwa.ad.group-read-request/v1.

    .PARAMETER Directory
        The directory accessor. Defaults to New-OgwaADDirectory. Tests pass a synthetic one.

    .PARAMETER ObservedAt
        The observation time recorded in the report. Defaults to now (UTC).

    .OUTPUTS
        System.Collections.Specialized.OrderedDictionary
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Request,
        [hashtable]$Directory,
        [datetime]$ObservedAt = [datetime]::UtcNow
    )

    $ErrorActionPreference = 'Stop'
    $report = New-OgwaReport -ObservedAt $ObservedAt
    $resolution = $report.resolution

    try {
        $report.request = ConvertTo-OgwaReadRequest -Request $Request
    }
    catch {
        $resolution.status = 'InvalidRequest'
        $resolution.error = Get-OgwaErrorText $_
        return $report
    }

    if (-not $PSBoundParameters.ContainsKey('Directory')) {
        try {
            $Directory = New-OgwaADDirectory
        }
        catch {
            $resolution.error = Get-OgwaErrorText $_
            return $report
        }
    }

    $context = New-OgwaContext -Directory $Directory -Request $report.request
    try {
        Initialize-OgwaForest -Context $context
        $report.forest = [ordered]@{ name = $context.ForestName; domains = @($context.DomainNames) }
        $match = Resolve-OgwaGroup -Context $context -Report $report
        if ($null -ne $match) {
            Read-OgwaGroupDetails -Context $context -Report $report -Match $match
        }
    }
    catch {
        if (Test-OgwaInvalidError $_) { $resolution.status = 'InvalidRequest' }
        elseif (Test-OgwaUnreachableError $_) { $resolution.status = 'Inconclusive' }
        else { $resolution.status = 'Failed' }
        $resolution.error = Get-OgwaErrorText $_
        # A report that failed part-way must not present half-read facts as a resolved group.
        if ($resolution.status -cne 'InvalidRequest' -and $null -ne $report.group) {
            $report.group = $null
        }
    }
    finally {
        $report.domains = @(ConvertTo-OgwaDomainSection -Context $context)
    }
    $report
}
