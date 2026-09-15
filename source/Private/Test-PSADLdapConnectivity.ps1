function Test-PSADLdapConnectivity
{
    <#
    .SYNOPSIS
        Tests whether a domain controller answers on an LDAP or LDAPS TCP port.

    .DESCRIPTION
        Performs a bounded TCP connect against a directory service port and returns a simple
        boolean. ICMP is deliberately not used because echo traffic is routinely blocked in
        Zero Trust and segmented Tier 0 networks, which would produce false negatives on a
        perfectly healthy domain controller. This mirrors the reachability strategy already
        used by Get-PSADDomainController.

        The connection attempt is always disposed in a finally block so that no socket handle
        leaks when a batch of domain controllers is processed through the pipeline.

    .PARAMETER ComputerName
        The host name, fully qualified domain name or IP address of the domain controller to
        probe. No name resolution is performed beyond what the TCP stack does.

    .PARAMETER Port
        The TCP port to probe. Defaults to 389 (LDAP). Use 636 for LDAPS or 3268 to validate
        a global catalog listener instead.

    .PARAMETER TimeoutMilliseconds
        The maximum time to wait for the TCP handshake to complete before declaring the
        domain controller unreachable. Defaults to 2000 milliseconds.

    .EXAMPLE
        Test-PSADLdapConnectivity -ComputerName 'DC01.corp.contoso.com'

        Returns true when the domain controller accepts LDAP connections on port 389.

    .EXAMPLE
        Test-PSADLdapConnectivity -ComputerName 'DC02.corp.contoso.com' -Port 636 -TimeoutMilliseconds 5000

        Probes the LDAPS listener with an extended timeout suitable for a high latency site link.

    .OUTPUTS
        System.Boolean

    .NOTES
        Internal helper. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ComputerName,

        [Parameter(Position = 1)]
        [ValidateRange(1, 65535)]
        [System.Int32]
        $Port = 389,

        [Parameter(Position = 2)]
        [ValidateRange(100, 120000)]
        [System.Int32]
        $TimeoutMilliseconds = 2000
    )

    process
    {
        $tcpClient = $null
        $isReachable = $false

        <#
            The handshake is timed so that the narration can report how close a domain
            controller ran to its budget. A site link that answers in 1 900 ms of a 2 000 ms
            budget is healthy today and an intermittent false negative tomorrow, and that is
            only visible if the elapsed time is reported rather than just the verdict.
        #>
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        Write-Verbose -Message ("Opening a TCP probe to '{0}' on port {1} with a {2} ms budget." -f $ComputerName, $Port, $TimeoutMilliseconds)

        try
        {
            $tcpClient = [System.Net.Sockets.TcpClient]::new()
            $connectTask = $tcpClient.ConnectAsync($ComputerName, $Port)

            if ($connectTask.Wait($TimeoutMilliseconds))
            {
                $isReachable = $tcpClient.Connected
            }
            else
            {
                Write-Verbose -Message ("Connection to '{0}' on port {1} timed out after {2} ms." -f $ComputerName, $Port, $TimeoutMilliseconds)
            }
        }
        catch [System.AggregateException]
        {
            # ConnectAsync surfaces socket and DNS faults wrapped in an AggregateException.
            $rootCause = $_.Exception.GetBaseException().Message
            Write-Verbose -Message ("Connection to '{0}' on port {1} failed: {2}" -f $ComputerName, $Port, $rootCause)
        }
        catch [System.Net.Sockets.SocketException]
        {
            Write-Verbose -Message ("Socket failure contacting '{0}' on port {1}: {2}" -f $ComputerName, $Port, $_.Exception.Message)
        }
        catch [System.Exception]
        {
            Write-Verbose -Message ("Unexpected failure contacting '{0}' on port {1}: {2}" -f $ComputerName, $Port, $_.Exception.Message)
        }
        finally
        {
            $stopwatch.Stop()

            if ($null -ne $tcpClient)
            {
                $tcpClient.Dispose()
            }
        }

        Write-Verbose -Message ("TCP probe of '{0}' on port {1} returned {2} after {3} ms of a {4} ms budget." -f $ComputerName, $Port, $isReachable, $stopwatch.ElapsedMilliseconds, $TimeoutMilliseconds)

        $isReachable
    }
}
