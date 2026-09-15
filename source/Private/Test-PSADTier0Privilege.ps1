function Test-PSADTier0Privilege
{
    <#
    .SYNOPSIS
        Evaluates a list of security identifiers for Tier 0 control plane membership.

    .DESCRIPTION
        Pure evaluation function that decides whether a security principal holds the Tier 0
        privileges required to reset a Directory Services Restore Mode password. No network
        or platform calls are made, which keeps the decision logic fully unit testable and
        independent of the mechanism used to collect the token groups.

        Membership is matched on well known relative identifiers rather than on group names,
        because group names are localised and renameable while RIDs are not:

          RID 512        Domain Admins
          RID 519        Enterprise Admins
          RID 518        Schema Admins
          S-1-5-32-544   BUILTIN\Administrators

        A DSRM password reset performed through ntdsutil requires administrative rights on
        the target domain controller, which in a correctly tiered forest is granted through
        Domain Admins or Enterprise Admins only.

    .PARAMETER SecurityIdentifier
        The collection of security identifier strings belonging to the principal being
        evaluated, typically the token groups of the caller. An empty collection is accepted
        and evaluates to a non Tier 0 result.

    .PARAMETER AllowBuiltinAdministrator
        Indicates that membership of the local BUILTIN\Administrators group (S-1-5-32-544)
        is sufficient. Disabled by default so that only domain scoped Tier 0 groups satisfy
        the check, which is the stricter Enterprise Access Model posture.

    .EXAMPLE
        Test-PSADTier0Privilege -SecurityIdentifier @('S-1-5-21-1111111111-2222222222-3333333333-512')

        Returns a result whose IsTier0 property is true because the Domain Admins RID is present.

    .EXAMPLE
        $sid = Get-PSADTokenGroupSid
        (Test-PSADTier0Privilege -SecurityIdentifier $sid).MatchedRole

        Reports which Tier 0 role granted the caller access.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        Internal helper. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        <#
            A mandatory parameter is implicitly treated as ValidateNotNullOrEmpty, which for a
            string array also rejects blank elements. The explicit Allow attributes are
            required so that a token group collection containing a null or blank entry is
            evaluated and fails closed, rather than throwing a binding error that a caller
            might mistake for an unrelated fault.
        #>
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [System.String[]]
        $SecurityIdentifier,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $AllowBuiltinAdministrator
    )

    begin
    {
        # Well known relative identifiers of the domain scoped Tier 0 groups.
        $tier0RelativeIdentifier = [ordered]@{
            '512' = 'Domain Admins'
            '519' = 'Enterprise Admins'
            '518' = 'Schema Admins'
        }

        $builtinAdministratorSid = 'S-1-5-32-544'
        $domainSidPattern = '^S-1-5-21-\d+-\d+-\d+-(?<rid>\d+)$'
    }

    process
    {
        $matchedSid = $null
        $matchedRole = $null

        $evaluatedSidCount = @($SecurityIdentifier).Where({ -not [System.String]::IsNullOrWhiteSpace($_) }).Count

        <#
            The narration reports counts and role names only. Security identifiers are never
            written to any stream: a token group set enumerates the complete privilege
            topology of a Tier 0 principal and is exactly the reconnaissance an attacker
            wants from a captured transcript.
        #>
        Write-Verbose -Message ('Evaluating {0} security identifier(s) for Tier 0 membership by well known relative identifier. The identifiers themselves are not narrated.' -f $evaluatedSidCount)

        foreach ($sid in @($SecurityIdentifier))
        {
            if ([System.String]::IsNullOrWhiteSpace($sid))
            {
                continue
            }

            $normalised = $sid.Trim()

            if ($AllowBuiltinAdministrator.IsPresent -and $normalised -eq $builtinAdministratorSid)
            {
                $matchedSid = $normalised
                $matchedRole = 'BUILTIN\Administrators'
                break
            }

            if ($normalised -match $domainSidPattern)
            {
                $relativeIdentifier = $Matches['rid']

                if ($tier0RelativeIdentifier.Contains($relativeIdentifier))
                {
                    $matchedSid = $normalised
                    $matchedRole = $tier0RelativeIdentifier[$relativeIdentifier]
                    break
                }
            }
        }

        $isTier0 = $null -ne $matchedRole

        if ($isTier0)
        {
            Write-Verbose -Message ("Tier 0 privilege confirmed through the role '{0}'." -f $matchedRole)
        }
        else
        {
            Write-Verbose -Message 'No Tier 0 group membership was found in the supplied security identifier collection.'
        }

        [PSCustomObject]@{
            IsTier0           = $isTier0
            MatchedRole       = $matchedRole
            MatchedSid        = $matchedSid
            EvaluatedSidCount = $evaluatedSidCount
        }
    }
}
