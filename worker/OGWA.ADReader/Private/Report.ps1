# The report skeleton and the per-run context (forest domains, contacted lazily).

function New-OgwaClassCounts {
    [ordered]@{ user = 0; computer = 0; group = 0; foreignSecurityPrincipal = 0; contact = 0; managedServiceAccount = 0; other = 0 }
}

function New-OgwaReport {
    # Every section starts NotApplicable; a section is filled only once the group is resolved.
    param([Parameter(Mandatory)][datetime]$ObservedAt)

    [ordered]@{
        schema                 = $script:Contract.reportSchema
        worker                 = [ordered]@{ name = $script:Contract.workerName; version = $script:Contract.workerVersion; readOnly = $true }
        observedAt             = ConvertTo-OgwaUtcText $ObservedAt
        request                = $null
        forest                 = $null
        domains                = @()
        resolution             = [ordered]@{
            status             = 'Failed'
            matchedBy          = $null
            searchedDomains    = @()
            unsearchedDomains  = @()
            candidates         = @()
            candidatesTruncated = $false
            error              = $null
        }
        group                  = $null
        directMembers          = [ordered]@{
            status       = 'NotApplicable'
            count        = $null
            byClass      = New-OgwaClassCounts
            memberGroups = @()
            unresolved   = 0
            error        = $null
        }
        nestedMembers          = [ordered]@{
            status                     = 'NotApplicable'
            groupsTraversed            = 0
            maxDepthObserved           = 0
            principalCount             = $null
            principalCountIsLowerBound = $false
            cycleDetected              = $false
            unexpandedReferences       = 0
            error                      = $null
        }
        primaryGroupReferences = [ordered]@{
            status            = 'NotApplicable'
            primaryGroupToken = $null
            count             = $null
            countIsLowerBound = $false
            searchedDomain    = $null
            error             = $null
        }
        memberOf               = [ordered]@{
            status            = 'NotApplicable'
            count             = $null
            countIsLowerBound = $false
            parents           = @()
            searchedDomains   = @()
            unsearchedDomains = @()
            error             = $null
        }
        protection             = [ordered]@{ status = 'Undetermined'; indicators = @(); error = $null }
    }
}

function New-OgwaGroupRef {
    param([Parameter(Mandatory)][object]$Summary, [Parameter(Mandatory)][string]$Domain)

    $sam = Get-OgwaValue $Summary 'SamAccountName'
    [ordered]@{
        objectGUID        = ConvertTo-OgwaGuidText (Get-OgwaValue $Summary 'ObjectGUID')
        objectSid         = ConvertTo-OgwaSidText (Get-OgwaValue $Summary 'ObjectSid')
        distinguishedName = [string](Get-OgwaValue $Summary 'DistinguishedName')
        samAccountName    = if ($null -eq $sam) { $null } else { [string]$sam }
        domain            = $Domain
    }
}

function ConvertTo-OgwaMemberClass {
    param([AllowEmptyString()][string]$ObjectClass)

    switch ($ObjectClass.ToLowerInvariant()) {
        'group' { 'group' }
        'user' { 'user' }
        'inetorgperson' { 'user' }
        'computer' { 'computer' }
        'foreignsecurityprincipal' { 'foreignSecurityPrincipal' }
        'contact' { 'contact' }
        'msds-groupmanagedserviceaccount' { 'managedServiceAccount' }
        'msds-managedserviceaccount' { 'managedServiceAccount' }
        'msds-delegatedmanagedserviceaccount' { 'managedServiceAccount' }
        default { 'other' }
    }
}

function New-OgwaContext {
    param([Parameter(Mandatory)][hashtable]$Directory, [Parameter(Mandatory)][object]$Request)

    @{
        Directory   = $Directory
        Request     = $Request
        ForestName  = $null
        DomainNames = [string[]]@()
        Domains     = @{}
    }
}

function Initialize-OgwaForest {
    # Reads the forest's domain list only. Domains are contacted later, and only if needed.
    param([Parameter(Mandatory)][hashtable]$Context)

    $forest = Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'GetForest'
    $names = @(Get-OgwaValue $forest 'Domains' | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $Context.ForestName = ([string](Get-OgwaValue $forest 'Name')).ToLowerInvariant()
    $Context.DomainNames = [string[]]$names
    foreach ($name in $names) {
        $Context.Domains[$name] = @{ DnsName = $name; Contacted = $false; Reachable = $null; Info = $null; Error = $null }
    }
}

function Get-OgwaDomain {
    # The domain's state, locating a domain controller on first use. $null if the name is
    # not a domain of this forest.
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$DnsName)

    $state = $Context.Domains[$DnsName.ToLowerInvariant()]
    if ($null -eq $state) { return $null }
    if (-not $state.Contacted) {
        $state.Contacted = $true
        try {
            $state.Info = Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'GetDomain' -ArgumentList @($state.DnsName)
            $state.Reachable = $true
        }
        catch {
            $state.Reachable = $false
            $state.Error = Get-OgwaErrorText $_
        }
    }
    $state
}

function Set-OgwaDomainUnreachable {
    # A domain that stops answering mid-run is not queried again in this run.
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $State.Reachable = $false
    $State.Error = Get-OgwaErrorText $ErrorRecord
}

function ConvertTo-OgwaDomainSection {
    param([Parameter(Mandatory)][hashtable]$Context)

    foreach ($name in $Context.DomainNames) {
        $state = $Context.Domains[$name]
        [ordered]@{ dnsName = $name; contacted = $state.Contacted; reachable = $state.Reachable; error = $state.Error }
    }
}
