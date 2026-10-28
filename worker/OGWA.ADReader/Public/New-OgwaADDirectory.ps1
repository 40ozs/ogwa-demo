function New-OgwaADDirectory {
    <#
    .SYNOPSIS
        Creates the default, read-only directory accessor backed by the ActiveDirectory module.

    .DESCRIPTION
        Returns a hashtable of read operations. Each operation is a single bounded query:
        a base or subtree search with an explicit result-size limit against one domain
        controller of one domain. Only these cmdlets are used: Get-ADForest, Get-ADDomain,
        Get-ADDomainController, Get-ADGroup and Get-ADObject.

        A domain controller that cannot be contacted is reported as unreachable, so the
        caller records the domain as unsearched instead of treating it as empty.

        Credentials are those of the calling process (for example the AAP machine
        credential). This function accepts no credential parameter.

    .OUTPUTS
        System.Collections.Hashtable
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if (-not (Get-Module -Name ActiveDirectory)) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'The ActiveDirectory PowerShell module (RSAT) is not installed on this host.'
        }
        Import-Module -Name ActiveDirectory -ErrorAction Stop -Verbose:$false
    }

    @{
        GetForest                   = {
            $forest = Invoke-OgwaADCall { Get-ADForest -ErrorAction Stop }
            @{ Name = [string]$forest.Name; Domains = @($forest.Domains | ForEach-Object { [string]$_ }) }
        }
        GetDomain                   = {
            param([string]$DnsName)
            # Any failure to locate or read a domain makes it unreachable for this run.
            Invoke-OgwaADCall -TreatFailureAsUnreachable {
                $locator = Get-ADDomainController -Discover -DomainName $DnsName -Service ADWS -ErrorAction Stop
                $server = [string]@($locator.HostName)[0]
                $domain = Get-ADDomain -Identity $DnsName -Server $server -ErrorAction Stop
                @{
                    DnsName           = [string]$domain.DNSRoot
                    DistinguishedName = [string]$domain.DistinguishedName
                    Sid               = [string]$domain.DomainSID.Value
                    Server            = $server
                }
            }
        }
        FindGroups                  = {
            param($Domain, [string]$By, [string]$Value, [int]$SizeLimit)
            $filter = New-OgwaGroupLookupFilter -By $By -Value $Value
            Invoke-OgwaADCall {
                Get-ADObject -LDAPFilter $filter -SearchBase $Domain.DistinguishedName -SearchScope Subtree -Server $Domain.Server -ResultSetSize $SizeLimit -Properties $script:SummaryProperties -ErrorAction Stop |
                    ForEach-Object { ConvertTo-OgwaSummary $_ }
            }
        }
        GetGroup                    = {
            param($Domain, [string]$DistinguishedName)
            Invoke-OgwaADCall {
                try {
                    $group = Get-ADGroup -Identity $DistinguishedName -Server $Domain.Server -Properties $script:GroupProperties -ErrorAction Stop
                }
                catch {
                    if ($_.Exception.GetType().FullName -eq 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException') { return $null }
                    throw
                }
                $sid = Get-OgwaValue $group 'SID'
                @{
                    DistinguishedName               = [string]$group.DistinguishedName
                    ObjectGUID                      = Get-OgwaValue $group 'ObjectGUID'
                    ObjectSid                       = if ($sid) { $sid.Value } else { $null }
                    SamAccountName                  = Get-OgwaValue $group 'SamAccountName'
                    Name                            = Get-OgwaValue $group 'Name'
                    GroupScope                      = [string](Get-OgwaValue $group 'GroupScope')
                    GroupCategory                   = [string](Get-OgwaValue $group 'GroupCategory')
                    AdminCount                      = Get-OgwaValue $group 'adminCount'
                    IsCriticalSystemObject          = Get-OgwaValue $group 'isCriticalSystemObject'
                    ProtectedFromAccidentalDeletion = Get-OgwaValue $group 'ProtectedFromAccidentalDeletion'
                    PrimaryGroupToken               = Get-OgwaValue $group 'primaryGroupToken'
                    WhenCreated                     = Get-OgwaValue $group 'whenCreated'
                    WhenChanged                     = Get-OgwaValue $group 'whenChanged'
                    Member                          = @(Get-OgwaValue $group 'member' | Where-Object { $_ } | ForEach-Object { [string]$_ })
                }
            }
        }
        GetObjectsByDn              = {
            param($Domain, [string[]]$DistinguishedNames)
            $clauses = @($DistinguishedNames | ForEach-Object { '(distinguishedName={0})' -f (ConvertTo-OgwaLdapFilterValue $_) })
            $filter = '(|' + ($clauses -join '') + ')'
            Invoke-OgwaADCall {
                Get-ADObject -LDAPFilter $filter -SearchBase $Domain.DistinguishedName -SearchScope Subtree -Server $Domain.Server -ResultSetSize $DistinguishedNames.Count -Properties $script:SummaryProperties -ErrorAction Stop |
                    ForEach-Object { ConvertTo-OgwaSummary $_ }
            }
        }
        CountPrimaryGroupReferences = {
            param($Domain, [long]$Rid, [int]$SizeLimit)
            Invoke-OgwaADCall {
                @(Get-ADObject -LDAPFilter "(primaryGroupID=$Rid)" -SearchBase $Domain.DistinguishedName -SearchScope Subtree -Server $Domain.Server -ResultSetSize $SizeLimit -ErrorAction Stop).Count
            }
        }
        FindParentGroups            = {
            param($Domain, [string]$MemberDn, [int]$SizeLimit)
            $filter = '(&(objectCategory=group)(member={0}))' -f (ConvertTo-OgwaLdapFilterValue $MemberDn)
            Invoke-OgwaADCall {
                Get-ADObject -LDAPFilter $filter -SearchBase $Domain.DistinguishedName -SearchScope Subtree -Server $Domain.Server -ResultSetSize $SizeLimit -Properties $script:SummaryProperties -ErrorAction Stop |
                    ForEach-Object { ConvertTo-OgwaSummary $_ }
            }
        }
    }
}
