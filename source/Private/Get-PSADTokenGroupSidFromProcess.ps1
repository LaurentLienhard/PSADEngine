function Get-PSADTokenGroupSidFromProcess
{
    <#
    .SYNOPSIS
        Reads the security identifiers present in the access token of the current process.

    .DESCRIPTION
        Wraps the WindowsIdentity access token enumeration in a disposable, unit mockable
        boundary. The access token is the authoritative source for an interactive Tier 0
        session because it is exactly the token that a child process such as ntdsutil.exe
        will inherit, including any group filtering applied by User Account Control or by a
        restricted or protected logon session.

        The user security identifier is returned alongside the group identifiers so that a
        caller can also evaluate rules keyed on the principal itself.

    .EXAMPLE
        Get-PSADTokenGroupSidFromProcess

        Returns the user security identifier followed by every group security identifier
        present in the current process access token.

    .OUTPUTS
        System.String[]

    .NOTES
        Internal helper. Not exported. Windows only.
    #>
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param ()

    begin
    {
        $isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
    }

    process
    {
        if (-not $isWindowsPlatform)
        {
            throw [System.PlatformNotSupportedException]::new(
                'Access token enumeration requires Windows. Run this Tier 0 operation from a Windows Privileged Access Workstation.')
        }

        $windowsIdentity = $null

        Write-Verbose -Message 'Enumerating the access token of the current process for its user and group security identifiers.'

        try
        {
            $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

            $securityIdentifier = [System.Collections.Generic.List[System.String]]::new()

            if ($null -ne $windowsIdentity.User)
            {
                $securityIdentifier.Add($windowsIdentity.User.Value)
            }

            foreach ($group in @($windowsIdentity.Groups))
            {
                $securityIdentifier.Add($group.Value)
            }

            <#
                Counts and the authentication context are narrated; the identifiers are not.
                A token group set maps the entire privilege topology of the principal and is
                exactly the reconnaissance worth harvesting from a captured transcript.
            #>
            Write-Verbose -Message ("Collected {0} security identifier(s) from the access token of '{1}'. Authenticated: {2}. The identifiers themselves are not narrated." -f $securityIdentifier.Count, $windowsIdentity.Name, $windowsIdentity.IsAuthenticated)

            return $securityIdentifier.ToArray()
        }
        catch [System.Security.SecurityException]
        {
            throw [System.Security.SecurityException]::new(
                ('The access token of the current process could not be inspected: {0}' -f $_.Exception.Message),
                $_.Exception)
        }
        finally
        {
            if ($null -ne $windowsIdentity)
            {
                $windowsIdentity.Dispose()
            }
        }
    }
}
