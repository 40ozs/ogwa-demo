function Remove-OgwaOktaGroupAssignment {
    <#
    .SYNOPSIS
        Dry-runs removing one Okta group's assignment to one application.

    .DESCRIPTION
        Both ids are explicit Okta ids, never names or patterns. Through the adapter: the
        assignment must exist, and a built-in group (such as Everyone) is refused.

        -ValidateOnly gives ValidationOnly, -WhatIf gives WhatIf, and an agreed
        confirmation removes the assignment from the synthetic adapter's in-memory world
        only (Simulated). This worker holds no Okta client and no credential; any other
        adapter is Blocked (NO_PRODUCTION_ADAPTER).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$OktaAppId,
        [Parameter(Mandatory)][AllowEmptyString()][string]$OktaGroupId,
        [Parameter(Mandatory)][AllowNull()][object]$Adapter,
        [switch]$ValidateOnly,
        [AllowNull()][AllowEmptyString()][string]$CorrelationId,
        [datetime]$ObservedAt = [datetime]::UtcNow
    )

    $result = New-OgwaRemediationResult -Operation 'OKTA_GROUP_UNASSIGN' -CorrelationId $CorrelationId -ObservedAt $ObservedAt
    $values = [ordered]@{ oktaAppId = $OktaAppId; oktaGroupId = $OktaGroupId }
    if (-not (Test-OgwaTargetValues -Result $result -Values $values)) { return Complete-OgwaRemediation -Result $result }
    if ($OktaAppId -cnotmatch $script:OktaIdPattern -or $OktaGroupId -cnotmatch $script:OktaIdPattern) {
        Stop-OgwaRemediation -Result $result -Code 'REQUEST_VALID' -Reason 'INVALID_REQUEST' -Detail 'Okta ids are 1-64 letters and digits'
        return Complete-OgwaRemediation -Result $result
    }
    $result.target = $values
    Add-OgwaCheck -Result $result -Code 'REQUEST_VALID' -Passed $true -Detail 'one explicit assignment, by application and group id'
    if (-not (Assert-OgwaSyntheticAdapter -Result $result -Adapter $Adapter)) { return Complete-OgwaRemediation -Result $result }
    if (-not $OktaAppId.StartsWith($script:SyntheticOktaAppPrefix) -or -not $OktaGroupId.StartsWith($script:SyntheticOktaGroupPrefix)) {
        Stop-OgwaRemediation -Result $result -Code 'TARGET_SYNTHETIC' -Reason 'NON_SYNTHETIC_TARGET' -Detail 'the synthetic adapter serves synthetic Okta ids only'
        return Complete-OgwaRemediation -Result $result
    }
    Add-OgwaCheck -Result $result -Code 'TARGET_SYNTHETIC' -Passed $true -Detail 'synthetic Okta ids'
    $found = Find-OgwaSyntheticAssignment -Adapter $Adapter -AppId $OktaAppId -GroupId $OktaGroupId
    if ($found.Count -ne 1) {
        Stop-OgwaRemediation -Result $result -Code 'ASSIGNMENT_PRESENT' -Reason 'ASSIGNMENT_NOT_FOUND' -Detail 'the group is not assigned to the application'
        return Complete-OgwaRemediation -Result $result
    }
    Add-OgwaCheck -Result $result -Code 'ASSIGNMENT_PRESENT' -Passed $true -Detail 'the assignment exists'
    if ($found[0].GroupType -ceq 'BUILT_IN') {
        Stop-OgwaRemediation -Result $result -Code 'GROUP_NOT_BUILT_IN' -Reason 'BUILT_IN_GROUP' -Detail 'a built-in Okta group is always protected'
        return Complete-OgwaRemediation -Result $result
    }
    Add-OgwaCheck -Result $result -Code 'GROUP_NOT_BUILT_IN' -Passed $true -Detail "group type $($found[0].GroupType)"

    $change = [ordered]@{
        action  = 'unassign_group_from_application'
        summary = "Remove the assignment of Okta group $OktaGroupId to application $OktaAppId."
        details = [ordered]@{ oktaAppId = $OktaAppId; oktaGroupId = $OktaGroupId }
    }
    if ($ValidateOnly) { return Complete-OgwaRemediation -Result $result -Outcome 'ValidationOnly' -Change $change }
    $targetText = "Okta assignment of group $OktaGroupId to application $OktaAppId"
    if ($PSCmdlet.ShouldProcess($targetText, 'Remove the assignment (OGWA remediation; synthetic adapter only)')) {
        try {
            Invoke-OgwaSyntheticChange -Adapter $Adapter -Change 'RemoveAssignment' -Arguments @{
                AppId = $OktaAppId; GroupId = $OktaGroupId
            }
        }
        catch {
            Add-OgwaBlockReason -Result $result -Reason 'ADAPTER_FAILED'
            return Complete-OgwaRemediation -Result $result
        }
        return Complete-OgwaRemediation -Result $result -Outcome 'Simulated' -Change $change
    }
    if ($WhatIfPreference) { return Complete-OgwaRemediation -Result $result -Outcome 'WhatIf' -Change $change }
    Add-OgwaBlockReason -Result $result -Reason 'CONFIRMATION_DECLINED'
    Complete-OgwaRemediation -Result $result
}
