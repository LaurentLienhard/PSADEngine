function Get-PSADServerScopeDefinition {
    <#
    .SYNOPSIS
        Generates agnostic IPv4 subnet definitions, range boundaries, and CIDR masks for any network scheme.
    .DESCRIPTION
        Provides fully decoupled, high-performance IPv4 subnet calculations via the SubnetCalculator class.
        Accepts explicit CIDR subnets or dynamic pattern templates (e.g. '10.{0}.2.0/24') combined with segment IDs.
        Computes network address, broadcast address, usable host ranges, default gateways, and total host counts
        using overflow-safe bitwise .NET operations.
    .PARAMETER Subnet
        Direct IPv4 subnet in CIDR notation (e.g. '10.1.2.0/24' or '192.168.100.0/22').
    .PARAMETER SubnetTemplate
        A format string pattern containing an index placeholder '{0}' for dynamic segment substitution (e.g. '172.16.{0}.0/23').
    .PARAMETER SegmentId
        An array of integer segment/site identifiers to inject into the SubnetTemplate.
    .PARAMETER GatewayStrategy
        Determines the default gateway IP calculation: FirstUsable (e.g. .1), LastUsable (e.g. .254), or None. Defaults to LastUsable.
    .EXAMPLE
        Get-PSADServerScopeDefinition -Subnet '10.10.2.0/24'
    .EXAMPLE
        Get-PSADServerScopeDefinition -SubnetTemplate '10.{0}.2.0/24' -SegmentId 1..5
    .EXAMPLE
        1..10 | Get-PSADServerScopeDefinition -SubnetTemplate '172.16.{0}.0/23' -GatewayStrategy FirstUsable
    #>
    [CmdletBinding(DefaultParameterSetName = 'DirectSubnet')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'DirectSubnet', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$')]
        [string]$Subnet,

        [Parameter(Mandatory = $true, ParameterSetName = 'TemplateSubnet')]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetTemplate,

        [Parameter(Mandatory = $true, ParameterSetName = 'TemplateSubnet', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [int[]]$SegmentId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('LastUsable', 'FirstUsable', 'None')]
        [string]$GatewayStrategy = 'LastUsable'
    )

    if ($PSCmdlet.ParameterSetName -eq 'DirectSubnet') {
        $calculator = [SubnetCalculator]::new($Subnet)
        $calculator.GatewayStrategy = $GatewayStrategy
        $calculator.Calculate()
    }
    else {
        $calculator = [SubnetCalculator]::new($SubnetTemplate, $SegmentId, $GatewayStrategy)
        $calculator.Calculate()
    }
}
