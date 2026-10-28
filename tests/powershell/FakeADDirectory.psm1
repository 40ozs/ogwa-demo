<#
    A synthetic, in-memory directory accessor for testing OGWA.ADReader.

    Every forest, domain, name, GUID and SID here is invented. The ".example" domains are
    reserved (RFC 2606) and never resolve. Nothing in this module contacts a directory.
#>
Set-StrictMode -Version 3.0

function New-SyntheticGuid {
    param([Parameter(Mandatory)][int]$Number)
    '5e7e7000-0000-4000-8000-{0:d12}' -f $Number
}

function New-SyntheticForest {
    [CmdletBinding()]
    param()

    $domains = [ordered]@{
        'corp.synthetic.example'      = @{ Dn = 'DC=corp,DC=synthetic,DC=example'; Sid = 'S-1-5-21-1000000001-1000000002-1000000003' }
        'emea.corp.synthetic.example' = @{ Dn = 'DC=emea,DC=corp,DC=synthetic,DC=example'; Sid = 'S-1-5-21-2000000001-2000000002-2000000003' }
        'apac.corp.synthetic.example' = @{ Dn = 'DC=apac,DC=corp,DC=synthetic,DC=example'; Sid = 'S-1-5-21-3000000001-3000000002-3000000003' }
    }
    $objects = [System.Collections.Generic.List[object]]::new()
    $created = [datetime]::new(2020, 1, 15, 9, 30, 0, [DateTimeKind]::Utc)
    $changed = [datetime]::new(2026, 6, 1, 8, 0, 0, [DateTimeKind]::Utc)

    $add = {
        param([string]$Domain, [string]$Class, [string]$Cn, [string]$Container, [int]$Rid, [hashtable]$Extra = @{})
        $domainInfo = $domains[$Domain]
        $object = @{
            Domain         = $Domain
            Class          = $Class
            Dn             = "CN=$Cn,$Container,$($domainInfo.Dn)"
            Name           = $Cn
            Sam            = $Cn
            Guid           = New-SyntheticGuid -Number ([int]($domainInfo.Sid.Substring(9, 1)) * 100000 + $Rid)
            Sid            = "$($domainInfo.Sid)-$Rid"
            GroupScope     = 'Global'
            GroupCategory  = 'Security'
            AdminCount     = $null
            Critical       = $false
            Protected      = $false
            PrimaryGroupId = $null
            Members        = @()
            WhenCreated    = $created
            WhenChanged    = $changed
        }
        foreach ($key in $Extra.Keys) { $object[$key] = $Extra[$key] }
        $objects.Add($object)
        $object
    }

    $corpGroups = 'OU=Groups'
    $corpUsers = 'OU=Users'
    $userOne = & $add 'corp.synthetic.example' 'user' 'SYNTH User One' $corpUsers 4201 @{ PrimaryGroupId = 513 }
    $userTwo = & $add 'corp.synthetic.example' 'user' 'SYNTH User Two' $corpUsers 4202 @{ PrimaryGroupId = 513 }
    $userThree = & $add 'corp.synthetic.example' 'user' 'SYNTH User Three' $corpUsers 4203 @{ PrimaryGroupId = 513 }
    $userFour = & $add 'emea.corp.synthetic.example' 'user' 'SYNTH User Four' $corpUsers 5204 @{ PrimaryGroupId = 513 }
    [void](& $add 'corp.synthetic.example' 'user' 'SYNTH Contractor One' $corpUsers 4204 @{ PrimaryGroupId = 4108 })
    [void](& $add 'corp.synthetic.example' 'computer' 'SYNTH-KIOSK-01' 'OU=Computers' 4206 @{ PrimaryGroupId = 4108 })

    # unique-group
    [void](& $add 'corp.synthetic.example' 'group' 'SYNTH-App-Payroll-Users' $corpGroups 4101 @{ Members = @($userOne.Dn, $userTwo.Dn) })
    # ambiguous-name: the same sAMAccountName in two domains
    [void](& $add 'corp.synthetic.example' 'group' 'SYNTH-App-Finance' $corpGroups 4102 @{ Members = @($userOne.Dn) })
    [void](& $add 'emea.corp.synthetic.example' 'group' 'SYNTH-App-Finance' $corpGroups 5102 @{ Members = @($userFour.Dn) })
    # unreachable-domain: unique in the reachable domains, but apac cannot be searched
    [void](& $add 'corp.synthetic.example' 'group' 'SYNTH-App-Claims' $corpGroups 4103 @{ Members = @($userTwo.Dn) })
    # nested-group: Parent -> Child -> (User Three, Grandchild -> (User Four, Parent: a cycle))
    $parent = & $add 'corp.synthetic.example' 'group' 'SYNTH-Nested-Parent' $corpGroups 4104 @{ GroupScope = 'Universal' }
    $child = & $add 'corp.synthetic.example' 'group' 'SYNTH-Nested-Child' $corpGroups 4105 @{ GroupScope = 'Universal' }
    $grandchild = & $add 'emea.corp.synthetic.example' 'group' 'SYNTH-Nested-Grandchild' $corpGroups 5106 @{ GroupScope = 'Universal' }
    [void](& $add 'emea.corp.synthetic.example' 'group' 'SYNTH-Resource-Access' $corpGroups 5107 @{ GroupScope = 'DomainLocal'; Members = @($parent.Dn) })
    $parent.Members = @($child.Dn)
    $child.Members = @($userThree.Dn, $grandchild.Dn)
    $grandchild.Members = @($userFour.Dn, $parent.Dn)
    # primary-group-dependency: no member values, but two objects use it as primary group
    [void](& $add 'corp.synthetic.example' 'group' 'SYNTH-Primary-Group-Contractors' $corpGroups 4108)
    # protected-group: empty, but adminCount is set and it is nested in Domain Admins
    $tier0 = & $add 'corp.synthetic.example' 'group' 'SYNTH-Tier0-Operators' 'OU=Tier0' 4109 @{ AdminCount = 1 }
    [void](& $add 'corp.synthetic.example' 'group' 'Domain Admins' 'CN=Users' 512 @{
            AdminCount = 1; Critical = $true; Protected = $true; Members = @($tier0.Dn)
        })
    # normal-empty-group
    [void](& $add 'corp.synthetic.example' 'group' 'SYNTH-Legacy-Empty' $corpGroups 4110)

    @{ ForestName = 'corp.synthetic.example'; Domains = $domains; Objects = $objects }
}

function Get-SyntheticObject {
    # Test helper: the synthetic object with this sAMAccountName in this domain.
    param([Parameter(Mandatory)][hashtable]$Forest, [Parameter(Mandatory)][string]$Domain, [Parameter(Mandatory)][string]$Sam)

    foreach ($object in $Forest.Objects) {
        if ($object.Domain -eq $Domain -and $object.Sam -eq $Sam) { return $object }
    }
    throw "no synthetic object $Sam in $Domain"
}

function New-FakeADDirectory {
    # A directory accessor over a synthetic forest. Domains in -UnreachableDomains fail like
    # a domain controller that does not answer. -Log records every operation.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Forest,
        [string[]]$UnreachableDomains = @(),
        [hashtable]$Overrides = @{}
    )

    $state = @{
        Forest      = $Forest
        Unreachable = $UnreachableDomains
        Overrides   = $Overrides
        Log         = [System.Collections.Generic.List[string]]::new()
    }
    @{
        Log                         = $state.Log
        GetForest                   = { Invoke-FakeADOperation -State $state -Operation 'GetForest' -Arguments @() }.GetNewClosure()
        GetDomain                   = { param($DnsName) Invoke-FakeADOperation -State $state -Operation 'GetDomain' -Arguments @($DnsName) }.GetNewClosure()
        FindGroups                  = { param($Domain, $By, $Value, $SizeLimit) Invoke-FakeADOperation -State $state -Operation 'FindGroups' -Arguments @($Domain, $By, $Value, $SizeLimit) }.GetNewClosure()
        GetGroup                    = { param($Domain, $DistinguishedName) Invoke-FakeADOperation -State $state -Operation 'GetGroup' -Arguments @($Domain, $DistinguishedName) }.GetNewClosure()
        GetObjectsByDn              = { param($Domain, $DistinguishedNames) Invoke-FakeADOperation -State $state -Operation 'GetObjectsByDn' -Arguments @($Domain, $DistinguishedNames) }.GetNewClosure()
        CountPrimaryGroupReferences = { param($Domain, $Rid, $SizeLimit) Invoke-FakeADOperation -State $state -Operation 'CountPrimaryGroupReferences' -Arguments @($Domain, $Rid, $SizeLimit) }.GetNewClosure()
        FindParentGroups            = { param($Domain, $MemberDn, $SizeLimit) Invoke-FakeADOperation -State $state -Operation 'FindParentGroups' -Arguments @($Domain, $MemberDn, $SizeLimit) }.GetNewClosure()
    }
}

function ConvertTo-FakeSummary {
    param([Parameter(Mandatory)][hashtable]$Object)

    @{
        DistinguishedName = $Object.Dn
        ObjectGUID        = [guid]$Object.Guid
        ObjectSid         = $Object.Sid
        SamAccountName    = $Object.Sam
        Name              = $Object.Name
        ObjectClass       = $Object.Class
    }
}

function Invoke-FakeADOperation {
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][string]$Operation, [object[]]$Arguments = @())

    $forest = $State.Forest
    $domainName = if ($Operation -eq 'GetDomain') { [string]$Arguments[0] } elseif ($Operation -ne 'GetForest') { [string]$Arguments[0].DnsName } else { '' }
    $State.Log.Add(("{0}:{1}" -f $Operation, $domainName).TrimEnd(':'))
    if ($State.Overrides.ContainsKey($Operation)) {
        return (& $State.Overrides[$Operation] $Arguments)
    }
    if ($Operation -ne 'GetForest' -and $State.Unreachable -contains $domainName) {
        throw "OGWA-UNREACHABLE: no synthetic domain controller for $domainName answered"
    }
    $inDomain = @($forest.Objects | Where-Object { $_.Domain -eq $domainName })

    switch ($Operation) {
        'GetForest' {
            return @{ Name = $forest.ForestName; Domains = @($forest.Domains.Keys) }
        }
        'GetDomain' {
            $info = $forest.Domains[$domainName]
            return @{ DnsName = $domainName; DistinguishedName = $info.Dn; Sid = $info.Sid; Server = "dc01.$domainName" }
        }
        'FindGroups' {
            $by = [string]$Arguments[1]
            $value = [string]$Arguments[2]
            $hits = [System.Collections.Generic.List[object]]::new()
            foreach ($object in $inDomain) {
                if ($object.Class -ne 'group') { continue }
                $isMatch = switch ($by) {
                    'objectGUID' { $object.Guid -eq $value }
                    'objectSid' { $object.Sid -ceq $value }
                    'distinguishedName' { $object.Dn -eq $value }
                    'samAccountName' { $object.Sam -eq $value }
                    'name' { $object.Name -eq $value -or $object.Sam -eq $value }
                    default { throw "unknown lookup $by" }
                }
                if ($isMatch -and $hits.Count -lt [int]$Arguments[3]) { $hits.Add((ConvertTo-FakeSummary $object)) }
            }
            return @($hits)
        }
        'GetGroup' {
            $object = $inDomain | Where-Object { $_.Class -eq 'group' -and $_.Dn -eq [string]$Arguments[1] } | Select-Object -First 1
            if ($null -eq $object) { return $null }
            return @{
                DistinguishedName               = $object.Dn
                ObjectGUID                      = [guid]$object.Guid
                ObjectSid                       = $object.Sid
                SamAccountName                  = $object.Sam
                Name                            = $object.Name
                GroupScope                      = $object.GroupScope
                GroupCategory                   = $object.GroupCategory
                AdminCount                      = $object.AdminCount
                IsCriticalSystemObject          = $object.Critical
                ProtectedFromAccidentalDeletion = $object.Protected
                PrimaryGroupToken               = [long]$object.Sid.Substring($object.Sid.LastIndexOf('-') + 1)
                WhenCreated                     = $object.WhenCreated
                WhenChanged                     = $object.WhenChanged
                Member                          = @($object.Members)
            }
        }
        'GetObjectsByDn' {
            $wanted = @($Arguments[1])
            return @($inDomain | Where-Object { $wanted -contains $_.Dn } | ForEach-Object { ConvertTo-FakeSummary $_ })
        }
        'CountPrimaryGroupReferences' {
            $count = @($inDomain | Where-Object { $_.PrimaryGroupId -eq [long]$Arguments[1] }).Count
            return [Math]::Min($count, [int]$Arguments[2])
        }
        'FindParentGroups' {
            $memberDn = [string]$Arguments[1]
            $hits = @($inDomain | Where-Object { $_.Class -eq 'group' -and @($_.Members) -contains $memberDn } | Select-Object -First ([int]$Arguments[2]))
            return @($hits | ForEach-Object { ConvertTo-FakeSummary $_ })
        }
        default { throw "unknown fake operation $Operation" }
    }
}

Export-ModuleMember -Function New-SyntheticForest, Get-SyntheticObject, New-FakeADDirectory, Invoke-FakeADOperation
