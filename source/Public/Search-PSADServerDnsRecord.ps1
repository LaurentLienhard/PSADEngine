function Search-PSADServerDnsRecord {
    <#
    .SYNOPSIS
        Searches AD-integrated DNS records by Name, IP/Target, Nature, Resource Record Type, and IP Scope.
    .DESCRIPTION
        Queries Active Directory integrated DNS zones using the DnsServer module via the DNSRecordSearcher class.
        Filters entries based on record nature (Static vs Dynamic), strictly validated Resource Record Types,
        and evaluates target IP addresses against an array of IP subnets (CIDR notation or IP prefixes)
        using high-performance bitwise subnet mask comparisons.
    .PARAMETER SearchTerm
        Optional IP address, IP prefix, HostName, or FQDN pattern to search for. Supports wildcard patterns (*).
    .PARAMETER RecordType
        Filters records by lifecycle nature: Static, Dynamic, or All. Defaults to All.
    .PARAMETER RRType
        Filters records by a validated list of DNS Resource Record Types. Defaults to All.
    .PARAMETER IPScope
        Optional array of IP Subnets in CIDR notation (e.g. '10.0.3.0/24', '10.1.0.0/16') or IP prefixes to filter records against.
    .PARAMETER ZoneName
        The target DNS zone name. Defaults to the current Active Directory domain root zone.
    .PARAMETER Server
        Target Domain Controller or DNS Server. Defaults to local context.
    .PARAMETER Credential
        Optional explicit PSCredential object for authenticating against the remote DNS server via CIM.
    .EXAMPLE
        Search-PSADServerDnsRecord -IPScope '10.0.3.0/24' -RecordType Dynamic -Server 'DC01.corp.contoso.com'
    .EXAMPLE
        Search-PSADServerDnsRecord -IPScope @('10.0.3.0/24', '10.1.2.0/24') -RRType 'A' -RecordType Static
    .EXAMPLE
        Search-PSADServerDnsRecord -SearchTerm 'caw1pbastion*' -RRType 'A' -Server 'DC01.corp.contoso.com' -Credential (Get-Credential)
    #>
    [CmdletBinding()]
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

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$IPScope,

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

    $searcher = [DNSRecordSearcher]::new()
    $searcher.SearchTerm = $SearchTerm
    $searcher.RecordType = $RecordType
    $searcher.RRType = $RRType
    $searcher.IPScope = $IPScope
    $searcher.ZoneName = $ZoneName
    $searcher.Server = $Server
    $searcher.Credential = $Credential

    $searcher.Search()
}
