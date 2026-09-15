function Resolve-PSADDsrmFailureDetail
{
    <#
    .SYNOPSIS
        Turns an error record raised during a DSRM reset into an actionable diagnosis.

    .DESCRIPTION
        Centralises the mapping between the exception types that a DSRM password reset can
        raise and the remediation an operator should perform. Keeping this mapping in one
        pure function means the calling Tier 0 function needs a single catch block rather
        than a stack of near identical typed catch blocks, which would duplicate the whole
        failure handling body once per exception type.

        The full inner exception chain is unwrapped and flattened into the returned detail.
        This matters for a DSRM reset because the actionable cause is almost always in the
        innermost exception: a DirectoryServicesCOMException wrapped in an
        UnauthorizedAccessException carries the real LDAP status, and the outer message alone
        would tell an operator nothing they can act on.

        The function never inspects, receives or emits password material.

    .PARAMETER ErrorRecord
        The error record captured by the calling catch block. Its exception chain is walked
        from the outermost exception inwards.

    .EXAMPLE
        try { throw [System.UnauthorizedAccessException]::new('denied') }
        catch { Resolve-PSADDsrmFailureDetail -ErrorRecord $_ }

        Returns a diagnosis whose Category is Authorization and whose Remediation describes
        the Tier 0 membership required.

    .EXAMPLE
        $diagnosis = Resolve-PSADDsrmFailureDetail -ErrorRecord $_
        $notes.Add($diagnosis.Detail)
        $notes.Add($diagnosis.Remediation)

        Appends both the flattened root cause and the remediation to an operation report.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        Internal helper. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    begin
    {
        $remediationByType = @{
            'System.UnauthorizedAccessException'                 = @{
                Category    = 'Authorization'
                Remediation = 'Confirm that the acting principal holds Domain Admins, Enterprise Admins or Schema Admins, that it can log on to the target domain controller, and that it is not filtered by an RODC Password Replication Policy.'
            }
            'System.Management.Automation.ItemNotFoundException' = @{
                Category    = 'TargetNotFound'
                Remediation = 'Verify the identity against Get-PSADDomainController. A DSRM reset must never be aimed at a member server or a decommissioned host.'
            }
            'System.InvalidOperationException'                   = @{
                Category    = 'OperationFailed'
                Remediation = 'Inspect the captured ntdsutil transcript, then confirm the DSRM state with dcdiag and repadmin before retrying.'
            }
            'System.TimeoutException'                            = @{
                Category    = 'Timeout'
                Remediation = 'The DSRM password state on the target is indeterminate because ntdsutil was terminated. Verify it by booting the domain controller into Directory Services Restore Mode, or re-run the reset once the host is responsive.'
            }
            'System.IO.FileNotFoundException'                    = @{
                Category    = 'MissingTooling'
                Remediation = 'Install the AD DS and AD LDS Tools feature of Remote Server Administration Tools on the management host so that ntdsutil.exe is available.'
            }
            'System.PlatformNotSupportedException'               = @{
                Category    = 'UnsupportedPlatform'
                Remediation = 'Run this Tier 0 operation from a Windows Privileged Access Workstation. ntdsutil.exe has no cross platform equivalent.'
            }
            'System.ArgumentException'                           = @{
                Category    = 'InvalidInput'
                Remediation = 'Correct the supplied identity or password so that it satisfies the documented Tier 0 constraints, then retry.'
            }
        }

        $defaultRemediation = @{
            Category    = 'Unclassified'
            Remediation = 'Review the flattened detail and the Windows event log records written under the PSADEngine source, then retry once the underlying condition is resolved.'
        }
    }

    process
    {
        $exception = $ErrorRecord.Exception

        $detail = $exception.Message
        $typeChain = [System.Collections.Generic.List[System.String]]::new()
        $typeChain.Add($exception.GetType().FullName)

        $inner = $exception.InnerException

        while ($null -ne $inner)
        {
            $detail = '{0} --> {1}' -f $detail, $inner.Message
            $typeChain.Add($inner.GetType().FullName)
            $inner = $inner.InnerException
        }

        # Match on the outermost type first, then walk inwards for a more specific diagnosis.
        $selected = $defaultRemediation

        foreach ($typeName in $typeChain)
        {
            if ($remediationByType.ContainsKey($typeName))
            {
                $selected = $remediationByType[$typeName]
                break
            }
        }

        [PSCustomObject]@{
            Detail        = $detail
            Category      = $selected.Category
            Remediation   = $selected.Remediation
            ExceptionType = $typeChain.ToArray()
        }
    }
}
