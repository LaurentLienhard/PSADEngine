function Search-PSADServerDnsRecord {
    <#
    .SYNOPSIS
        Searches AD-integrated DNS records by Name, IP/Target, Nature, Resource Record Type, and IP Scope.
    .DESCRIPTION
        Queries Active Directory integrated DNS zones using the DnsServer module via the DNSNetworkSearcher class.
        Filters entries based on record nature (Static vs Dynamic), strictly validated Resource Record Types,
        and evaluates target IP addresses against IP subnets (direct CIDR, direct prefixes, or calculated from template + segment IDs)
        using high-performance bitwise subnet mask comparisons.
    .PARAMETER SearchTerm
        Optional IP address, IP prefix, HostName, or FQDN pattern to search for. Supports wildcard patterns (*).
    .PARAMETER RecordType
        Filters records by lifecycle nature: Static, Dynamic, or All. Defaults to All.
    .PARAMETER RRType
        Filters records by a validated list of DNS Resource Record Types. Defaults to All.
    .PARAMETER Subnet
        Direct IPv4 subnet in CIDR notation (e.g. '10.1.2.0/24'). Mutually exclusive with SubnetTemplate/SegmentId.
    .PARAMETER SubnetTemplate
        Format string pattern containing placeholder '{0}' for dynamic segment substitution (e.g. '172.16.{0}.0/23').
        Requires SegmentId parameter. Mutually exclusive with Subnet.
    .PARAMETER SegmentId
        Array of integer segment/site identifiers to inject into SubnetTemplate. Requires SubnetTemplate parameter.
    .PARAMETER GatewayStrategy
        Determines the default gateway IP calculation: FirstUsable, LastUsable, or None. Defaults to LastUsable.
        (Note: Used internally for subnet calculation; not exposed in DNS search results)
    .PARAMETER ZoneName
        The target DNS zone name. Defaults to the current Active Directory domain root zone.
    .PARAMETER Server
        Target Domain Controller or DNS Server. Defaults to local context.
    .PARAMETER Credential
        Optional explicit PSCredential object for authenticating against the remote DNS server via CIM.
    .EXAMPLE
        Search-PSADServerDnsRecord -Subnet '10.0.3.0/24' -RecordType Dynamic -Server 'DC01.corp.contoso.com'
    .EXAMPLE
        Search-PSADServerDnsRecord -SubnetTemplate '10.{0}.2.0/24' -SegmentId 1..5 -RRType 'A' -RecordType Static
    .EXAMPLE
        Search-PSADServerDnsRecord -SearchTerm 'caw1pbastion*' -RRType 'A' -Server 'DC01.corp.contoso.com' -Credential (Get-Credential)
    #>
    [CmdletBinding(DefaultParameterSetName = 'Direct')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchTerm,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Static', 'Dynamic', 'All')]
        [string]$RecordType = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateSet('A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'MX', 'SRV', 'SOA', 'NS', 'All')]
        [string[]]$RRType = @('All'),

        [Parameter(Mandatory = $false, ParameterSetName = 'Direct')]
        [ValidatePattern('^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$')]
        [string]$Subnet,

        [Parameter(Mandatory = $true, ParameterSetName = 'Template')]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetTemplate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Template', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [int[]]$SegmentId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('LastUsable', 'FirstUsable', 'None')]
        [string]$GatewayStrategy = 'LastUsable',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ZoneName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    $searcher = [DNSNetworkSearcher]::new()
    $searcher.SearchTerm = $SearchTerm
    $searcher.RecordType = $RecordType
    $searcher.RRType = $RRType
    $searcher.Subnet = $Subnet
    $searcher.SubnetTemplate = $SubnetTemplate
    $searcher.SegmentId = $SegmentId
    $searcher.GatewayStrategy = $GatewayStrategy
    $searcher.ZoneName = $ZoneName
    $searcher.Server = $Server
    $searcher.Credential = $Credential

    $searcher.Search()
}
