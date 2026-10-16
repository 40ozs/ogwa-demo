function Move-OgwaADGroupToQuarantine {
    <#
    .SYNOPSIS
        Dry-runs moving one AD group, named by objectGUID in its domain, into a quarantine OU.

    .DESCRIPTION
        The same checks as Remove-OgwaADGroup (explicit target, one group by objectGUID,
        identity re-verified, protection refused, no members or parent groups), plus: the
        quarantine OU must exist in the group's own domain, and the group must not already
        be in it. The OU comes from OGWA's server-side allowlist, never from a person.

        -ValidateOnly gives ValidationOnly, -WhatIf gives WhatIf, and an agreed
        confirmation moves the group in the synthetic adapter's in-memory world only
        (Simulated). Any other adapter is Blocked (NO_PRODUCTION_ADAPTER).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ObjectGuid,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Domain,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ExpectedSid,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ExpectedDistinguishedName,
        [Parameter(Mandatory)][AllowEmptyString()][string]$QuarantineOu,
        [Parameter(Mandatory)][AllowNull()][object]$Adapter,
        [switch]$ValidateOnly,
        [AllowNull()][AllowEmptyString()][string]$CorrelationId,
        [datetime]$ObservedAt = [datetime]::UtcNow
    )

    $result = New-OgwaRemediationResult -Operation 'AD_GROUP_QUARANTINE' -CorrelationId $CorrelationId -ObservedAt $ObservedAt
    $values = [ordered]@{
        objectGuid = $ObjectGuid; domain = $Domain; expectedSid = $ExpectedSid
        expectedDistinguishedName = $ExpectedDistinguishedName; quarantineOu = $QuarantineOu
    }
    if (-not (Test-OgwaADTargetRequest -Result $result -Values $values)) { return Complete-OgwaRemediation -Result $result }
    $group = Resolve-OgwaADTarget -Result $result -Values $values -Adapter $Adapter
    if ($null -eq $group) { return Complete-OgwaRemediation -Result $result }
    if (-not (Test-OgwaGroupIsEmpty -Result $result -Group $group)) { return Complete-OgwaRemediation -Result $result }
    if (-not (Test-OgwaSyntheticOrganizationalUnit -Adapter $Adapter -DistinguishedName $QuarantineOu)) {
        Stop-OgwaRemediation -Result $result -Code 'QUARANTINE_OU_VALID' -Reason 'QUARANTINE_OU_INVALID' -Detail 'the quarantine OU does not exist in the group''s domain'
        return Complete-OgwaRemediation -Result $result
    }
    $rdn, $parent = Split-OgwaDn -DistinguishedName $group.DistinguishedName
    if ($parent.Equals($QuarantineOu, [StringComparison]::OrdinalIgnoreCase)) {
        Stop-OgwaRemediation -Result $result -Code 'QUARANTINE_OU_VALID' -Reason 'ALREADY_IN_QUARANTINE' -Detail 'the group is already in the quarantine OU'
        return Complete-OgwaRemediation -Result $result
    }
    Add-OgwaCheck -Result $result -Code 'QUARANTINE_OU_VALID' -Passed $true -Detail 'an existing OU in the group''s domain'

    $moved = "$rdn,$QuarantineOu"
    $change = [ordered]@{
        action  = 'move_group_to_quarantine'
        summary = "Move AD group $($group.SamAccountName) ($($group.ObjectGuid)) into the quarantine OU."
        details = [ordered]@{
            'after.distinguishedName' = $moved; 'before.distinguishedName' = $group.DistinguishedName
            domain = $group.Domain; objectGUID = $group.ObjectGuid
        }
    }
    if ($ValidateOnly) { return Complete-OgwaRemediation -Result $result -Outcome 'ValidationOnly' -Change $change }
    $targetText = "AD group $($group.SamAccountName) ($($group.ObjectGuid)) in $($group.Domain)"
    if ($PSCmdlet.ShouldProcess($targetText, "Move the group to $QuarantineOu (OGWA remediation; synthetic adapter only)")) {
        try {
            Invoke-OgwaSyntheticChange -Adapter $Adapter -Change 'MoveGroup' -Arguments @{
                ObjectGuid = $group.ObjectGuid; Domain = $group.Domain; DistinguishedName = $moved
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
