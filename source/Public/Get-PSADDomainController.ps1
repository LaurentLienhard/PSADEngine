function Get-PSADDomainController
{
    <#
    .SYNOPSIS
        Retrieves the list of all domain controllers for the current or a specified domain.
    .DESCRIPTION
        Utilizes native .NET classes to query Active Directory and returns strongly-typed objects.
        This method is robust as it does not require the ActiveDirectory (RSAT) module.
        It evaluates DC reachability by checking LDAP port (389) connectivity rather than relying on ICMP, which is often blocked in Zero Trust environments.
    .PARAMETER DomainName
        (Optional) The FQDN of the domain (e.g., contoso.com). If not specified, the function uses the domain the machine is joined to.
    .EXAMPLE
        Get-PSADDomainController
    .EXAMPLE
        Get-PSADDomainController -DomainName "contoso.com"
    .OUTPUTS
        PSADDomainController
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([PSADDomainController])]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName
    )

    begin
    {
        # Initialize output collection with strong typing
        $Results = [System.Collections.Generic.List[PSADDomainController]]::new()
    }

    process
    {
        $targetDomain = if ([string]::IsNullOrWhiteSpace($DomainName))
        {
            "Current Domain"
        }
        else
        {
            $DomainName
        }

        if ($PSCmdlet.ShouldProcess($targetDomain, "Retrieve Domain Controllers"))
        {
            try
            {
                if ([string]::IsNullOrWhiteSpace($DomainName))
                {
                    Write-Verbose "Querying current machine's domain."
                    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                }
                else
                {
                    Write-Verbose "Connecting to specific domain: $DomainName"
                    $Context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)
                    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($Context)
                }

                foreach ($DC in $Domain.DomainControllers)
                {
                    Write-Verbose "Processing domain controller: $($DC.Name)"

                    try
                    {
                        # Zero Trust / Tier 0 approach: ICMP is often blocked, test LDAP port (389)
                        $isReachable = $false
                        try
                        {
                            $tcpClient = [System.Net.Sockets.TcpClient]::new()
                            $asyncResult = $tcpClient.BeginConnect($DC.Name, 389, $null, $null)
                            # Wait up to 2000 milliseconds for connection
                            $isReachable = $asyncResult.AsyncWaitHandle.WaitOne(2000, $true)
                            $tcpClient.Close()
                        }
                        catch
                        {
                            $isReachable = $false
                        }

                        if (-not $isReachable)
                        {
                            Write-Warning "Domain Controller $($DC.Name) is unreachable (LDAP port 389 test failed)."
                            $dcObj = [PSADDomainController]@{
                                Name = $DC.Name
                                IPAddress = ""
                                IsReachable = $false
                                OperatingSystemVersion = ""
                                FSMORoles = ""
                                SiteName = $DC.SiteName # Might be available via cached AD topology
                                IsGlobalCatalog = $false
                            }
                            $Results.Add($dcObj)
                            continue
                        }

                        $dcObj = [PSADDomainController]@{
                            Name = $DC.Name
                            IPAddress = $DC.IPAddress
                            IsReachable = $isReachable
                            OperatingSystemVersion = $DC.OSVersion
                            FSMORoles = ($DC.Roles -join ', ')
                            SiteName = $DC.SiteName
                            IsGlobalCatalog = $DC.IsGlobalCatalog()
                        }
                        $Results.Add($dcObj)

                    }
                    catch
                    {
                        Write-Warning "Unable to retrieve all information for $($DC.Name): $_"
                        $dcObj = [PSADDomainController]@{
                            Name = $DC.Name
                            IPAddress = ""
                            IsReachable = $false
                            OperatingSystemVersion = ""
                            FSMORoles = ""
                            SiteName = $DC.SiteName # Might be available via cached AD topology
                            IsGlobalCatalog = $false
                        }
                        $Results.Add($dcObj)
                    }
                }
            }
            catch
            {
                Write-Error "Error retrieving domain controllers: $_"
            }
        }
    }

    end
    {
        # Output the results to the pipeline
        if ($Results.Count -gt 0)
        {
            $Results.ToArray()
        }
    }
}
