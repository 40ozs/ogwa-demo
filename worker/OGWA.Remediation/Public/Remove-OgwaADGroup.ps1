function Remove-OgwaADGroup {
    <#
    .SYNOPSIS
        Dry-runs the deletion of one AD group, named by objectGUID in its domain.

    .DESCRIPTION
        Validates the explicit target, then, through the adapter: resolves exactly one group
        by objectGUID, re-verifies the objectSid and distinguishedName OGWA approved, refuses
        any protected group (adminCount, ProtectedFromAccidentalDeletion, critical system
        object, well-known SID; unknown protection also blocks), and refuses a group with
        members or parent groups.

        -ValidateOnly stops there (ValidationOnly). Otherwise ShouldProcess decides: -WhatIf
        gives WhatIf; an agreed confirmation applies the deletion to the synthetic adapter's
        in-memory world only (Simulated). There is no production adapter: any other adapter
        is Blocked (NO_PRODUCTION_ADAPTER).

    .EXAMPLE
        Remove-OgwaADGroup -ObjectGuid $guid -Domain corp.synthetic.example -ExpectedSid $sid `
            -ExpectedDistinguishedName $dn -Adapter $syntheticAdapter -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ObjectGuid,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Domain,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ExpectedSid,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ExpectedDistinguishedName,
        [Parameter(Mandatory)][AllowNull()][object]$Adapter,
        [switch]$ValidateOnly,
        [AllowNull()][AllowEmptyString()][string]$CorrelationId,
        [datetime]$ObservedAt = [datetime]::UtcNow
    )

    $result = New-OgwaRemediationResult -Operation 'AD_GROUP_DELETE' -CorrelationId $CorrelationId -ObservedAt $ObservedAt
    $values = [ordered]@{
        objectGuid = $ObjectGuid; domain = $Domain; expectedSid = $ExpectedSid
        expectedDistinguishedName = $ExpectedDistinguishedName
    }
    if (-not (Test-OgwaADTargetRequest -Result $result -Values $values)) { return Complete-OgwaRemediation -Result $result }
    $group = Resolve-OgwaADTarget -Result $result -Values $values -Adapter $Adapter
    if ($null -eq $group) { return Complete-OgwaRemediation -Result $result }
    if (-not (Test-OgwaGroupIsEmpty -Result $result -Group $group)) { return Complete-OgwaRemediation -Result $result }

    $change = [ordered]@{
        action  = 'delete_group'
        summary = "Delete AD group $($group.SamAccountName) ($($group.ObjectGuid)) in $($group.Domain)."
        details = [ordered]@{
            distinguishedName = $group.DistinguishedName; domain = $group.Domain; objectGUID = $group.ObjectGuid
            objectSid = $group.Sid
        }
    }
    if ($ValidateOnly) { return Complete-OgwaRemediation -Result $result -Outcome 'ValidationOnly' -Change $change }
    $targetText = "AD group $($group.SamAccountName) ($($group.ObjectGuid)) in $($group.Domain)"
    if ($PSCmdlet.ShouldProcess($targetText, 'Delete the group (OGWA remediation; synthetic adapter only)')) {
        try {
            Invoke-OgwaSyntheticChange -Adapter $Adapter -Change 'RemoveGroup' -Arguments @{
                ObjectGuid = $group.ObjectGuid; Domain = $group.Domain
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
