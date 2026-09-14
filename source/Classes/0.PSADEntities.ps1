<#
.SYNOPSIS
    Defines the base class for a standard computer.
#>
class PSADComputer
{
    [string]$Name
    [string]$IPAddress
    [bool]$IsReachable
    [string]$DistinguishedName
    [string]$DNSHostName
    [bool]$Enabled
    [datetime]$LastLogonTimestamp
    [string]$Description
    [string]$ObjectGUID
    [string]$OperatingSystem
    [string]$OperatingSystemVersion

    PSADComputer()
    {
    }
}

<#
.SYNOPSIS
    Defines a server class, inheriting from PSADComputer.
#>
class PSADServer : PSADComputer
{
    [string]$Role

    PSADServer()
    {
    }
}

<#
.SYNOPSIS
    Defines a Domain Controller class, inheriting from PSADServer.
#>
class PSADDomainController : PSADServer
{
    [string]$FSMORoles
    [string]$SiteName
    [bool]$IsGlobalCatalog

    PSADDomainController()
    {
    }
}

# Configure default display properties for the console
Update-TypeData -TypeName 'PSADDomainController' -DefaultDisplayPropertySet Name, SiteName, IsGlobalCatalog, FSMORoles, IPAddress, IsReachable, OperatingSystemVersion -Force
