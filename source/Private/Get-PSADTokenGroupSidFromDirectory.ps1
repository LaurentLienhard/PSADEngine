function Get-PSADTokenGroupSidFromDirectory
{
    <#
    .SYNOPSIS
        Reads the transitive tokenGroups membership of an account over LDAP.

    .DESCRIPTION
        Binds to the directory with the supplied credential, locates the matching account and
        reads the constructed tokenGroups attribute. tokenGroups is computed by the domain
        controller itself and already contains nested groups, domain local groups and well
        known identities, so it is both faster and more correct than a recursive memberOf
        walk, which silently misses primary group membership and cross domain nesting.

        Every DirectoryEntry and DirectorySearcher is disposed in a finally block so that a
        batch operation cannot leak LDAP connections against a Tier 0 host. SearchResult is
        deliberately absent from that teardown because it does not implement IDisposable.

        Exception handling uses the base exception type and inspects the concrete type name
        at runtime rather than declaring System.DirectoryServices types in catch clauses.
        PowerShell resolves catch clause types when the script block is compiled, so a typed
        catch on a Windows only assembly would turn module import into a parse error on any
        other platform, including a cross platform build agent.

        SECURITY: the account name is escaped according to RFC 4515 before it is placed in
        the LDAP filter. Without this escaping an account name containing filter
        metacharacters could alter the search semantics and cause the privilege check to
        match the wrong principal.

    .PARAMETER Credential
        The credential to bind with and whose transitive group membership is returned. The
        password is handed directly to the directory bind and is never written to any stream.

    .PARAMETER Server
        The domain controller or domain name to bind against. When omitted, the serverless
        LDAP binding path is used and the client locator selects a domain controller.

    .EXAMPLE
        Get-PSADTokenGroupSidFromDirectory -Credential $adminCredential -Server 'DC01.corp.contoso.com'

        Returns every security identifier that the domain controller computes for the account.

    .OUTPUTS
        System.String[]

    .NOTES
        Internal helper. Not exported. Windows only; System.DirectoryServices is not
        functional on other platforms.
    #>
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Position = 1)]
        [AllowEmptyString()]
        [AllowNull()]
        [System.String]
        $Server
    )

    begin
    {
        $tokenGroupsAttribute = 'tokenGroups'
        $isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
        $accessDeniedTypeName = @(
            'System.DirectoryServices.DirectoryServicesCOMException'
            'System.UnauthorizedAccessException'
        )
    }

    process
    {
        if (-not $isWindowsPlatform)
        {
            throw [System.PlatformNotSupportedException]::new(
                'System.DirectoryServices is not functional outside Windows. Run this Tier 0 operation from a Windows Privileged Access Workstation.')
        }

        $useServer = -not [System.String]::IsNullOrWhiteSpace($Server)
        $networkCredential = $Credential.GetNetworkCredential()
        $rootEntry = $null
        $searchRoot = $null
        $searcher = $null
        $userEntry = $null

        try
        {
            $rootPath = if ($useServer) { 'LDAP://{0}/RootDSE' -f $Server } else { 'LDAP://RootDSE' }

            $rootEntry = [System.DirectoryServices.DirectoryEntry]::new(
                $rootPath, $Credential.UserName, $networkCredential.Password)

            $defaultNamingContext = $rootEntry.Properties['defaultNamingContext'].Value

            if ([System.String]::IsNullOrWhiteSpace($defaultNamingContext))
            {
                throw [System.InvalidOperationException]::new(
                    'The directory bind succeeded but RootDSE did not expose a defaultNamingContext. The target is not an Active Directory domain controller.')
            }

            $searchPath = if ($useServer)
            {
                'LDAP://{0}/{1}' -f $Server, $defaultNamingContext
            }
            else
            {
                'LDAP://{0}' -f $defaultNamingContext
            }

            $searchRoot = [System.DirectoryServices.DirectoryEntry]::new(
                $searchPath, $Credential.UserName, $networkCredential.Password)

            # RFC 4515 escaping of every value placed into the LDAP filter.
            $samAccountName = Format-PSADLdapFilterValue -Value $networkCredential.UserName
            $userPrincipalName = Format-PSADLdapFilterValue -Value $Credential.UserName

            $searcher = [System.DirectoryServices.DirectorySearcher]::new($searchRoot)
            $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={0})(userPrincipalName={1})))' -f $samAccountName, $userPrincipalName
            $searcher.SizeLimit = 1
            $null = $searcher.PropertiesToLoad.Add('distinguishedName')

            $searchResult = $searcher.FindOne()

            if ($null -eq $searchResult)
            {
                throw [System.Management.Automation.ItemNotFoundException]::new(
                    ("The account '{0}' could not be located in the directory, so its Tier 0 privileges cannot be evaluated." -f $Credential.UserName))
            }

            $userEntry = $searchResult.GetDirectoryEntry()
            $userEntry.RefreshCache(@($tokenGroupsAttribute))

            $securityIdentifier = [System.Collections.Generic.List[System.String]]::new()

            foreach ($rawSid in @($userEntry.Properties[$tokenGroupsAttribute]))
            {
                $securityIdentifier.Add(
                    [System.Security.Principal.SecurityIdentifier]::new([System.Byte[]]$rawSid, 0).Value)
            }

            return $securityIdentifier.ToArray()
        }
        catch [System.Management.Automation.ItemNotFoundException]
        {
            throw
        }
        catch [System.Exception]
        {
            $concreteTypeName = $_.Exception.GetType().FullName

            if ($accessDeniedTypeName -contains $concreteTypeName)
            {
                throw [System.UnauthorizedAccessException]::new(
                    ('The directory bind used to evaluate Tier 0 privileges failed for {0}: {1}' -f $Credential.UserName, $_.Exception.Message),
                    $_.Exception)
            }

            throw [System.InvalidOperationException]::new(
                ('Tier 0 privilege evaluation over LDAP failed ({0}): {1}' -f $concreteTypeName, $_.Exception.Message),
                $_.Exception)
        }
        finally
        {
            # Deterministic teardown; LDAP handles must not survive a Tier 0 batch.
            foreach ($disposable in @($userEntry, $searcher, $searchRoot, $rootEntry))
            {
                if ($null -ne $disposable)
                {
                    $disposable.Dispose()
                }
            }

            $networkCredential = $null
        }
    }
}
