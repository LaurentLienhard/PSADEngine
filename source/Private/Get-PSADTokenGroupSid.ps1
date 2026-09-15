function Get-PSADTokenGroupSid
{
    <#
    .SYNOPSIS
        Returns the transitive security identifiers of the calling or supplied principal.

    .DESCRIPTION
        Collects the complete, transitively expanded group membership of a security principal
        as a flat list of security identifier strings, which is what Test-PSADTier0Privilege
        needs in order to decide whether a Tier 0 operation may proceed.

        Two collection strategies are used:

          - No credential supplied: the groups are read from the access token of the current
            process through WindowsIdentity. This is authoritative because it reflects the
            token that ntdsutil will actually run under.

          - Credential supplied: the constructed tokenGroups attribute of the account is read
            over LDAP using that credential. tokenGroups is computed by the domain controller
            and already contains nested and domain local memberships, so no recursive group
            walk is required and no membership can be missed.

        Results are cached in module scope for the lifetime of the session and keyed on the
        account name and target server. This is the credential caching contract required for
        batch operations: a pipeline that resets the DSRM password on twenty domain
        controllers performs exactly one privilege evaluation instead of twenty LDAP binds.
        Use the Refresh switch to force re-evaluation after a group membership change.

    .PARAMETER Credential
        The credential whose transitive group membership should be evaluated. When omitted,
        the access token of the current process is inspected instead, which is the correct
        behaviour for an interactive Privileged Access Workstation session.

    .PARAMETER Server
        The domain controller or domain name to bind against when a credential is supplied.
        When omitted the client locator selects a domain controller automatically. Ignored
        when no credential is supplied.

    .PARAMETER Refresh
        Forces the cached result for the resolved cache key to be discarded and recomputed.
        Use this after a group membership change so that a stale allow or deny decision is
        not reused within the same PowerShell session.

    .EXAMPLE
        Get-PSADTokenGroupSid

        Returns every security identifier present in the access token of the current process.

    .EXAMPLE
        $sidParam = @{
            Credential = $adminCredential
            Server     = 'DC01.corp.contoso.com'
        }
        Get-PSADTokenGroupSid @sidParam

        Reads the transitive membership of an alternate Tier 0 account over LDAP.

    .OUTPUTS
        System.String[]

    .NOTES
        Internal helper. Not exported. Requires Windows; System.DirectoryServices and
        WindowsIdentity are not available on other platforms.
    #>
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param
    (
        [Parameter(Position = 0)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Server,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Refresh
    )

    begin
    {
        if ($null -eq $script:PSADTokenGroupSidCache)
        {
            $script:PSADTokenGroupSidCache = @{}
        }

        $currentTokenCacheKey = 'CURRENT-PROCESS-TOKEN'
    }

    process
    {
        $useCredential = ($null -ne $Credential) -and
            ($Credential -ne [System.Management.Automation.PSCredential]::Empty) -and
            (-not [System.String]::IsNullOrWhiteSpace($Credential.UserName))

        $cacheKey = if ($useCredential)
        {
            '{0}|{1}' -f $Credential.UserName, $Server
        }
        else
        {
            $currentTokenCacheKey
        }

        if (-not $Refresh.IsPresent -and $script:PSADTokenGroupSidCache.ContainsKey($cacheKey))
        {
            Write-Verbose -Message ("Returning the cached token group set for the cache key '{0}'." -f $cacheKey)
            return $script:PSADTokenGroupSidCache[$cacheKey]
        }

        <#
            The platform guard lives in the two collector functions rather than here, so that
            this dispatch and cache layer stays platform neutral and fully unit testable.
        #>
        $securityIdentifier = if ($useCredential)
        {
            Get-PSADTokenGroupSidFromDirectory -Credential $Credential -Server $Server
        }
        else
        {
            Get-PSADTokenGroupSidFromProcess
        }

        $script:PSADTokenGroupSidCache[$cacheKey] = $securityIdentifier

        Write-Verbose -Message ('Collected {0} security identifiers for the cache key ''{1}''.' -f @($securityIdentifier).Count, $cacheKey)

        return $securityIdentifier
    }
}
