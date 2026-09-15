function ConvertFrom-PSADNtdsutilOutput
{
    <#
    .SYNOPSIS
        Translates raw ntdsutil console output into a structured success or failure verdict.

    .DESCRIPTION
        ntdsutil.exe is an interactive maintenance tool, not an automation surface. It
        reports nearly every outcome with exit code 0 and communicates the real result only
        through localisable console text. This function isolates that fragile parsing into a
        single pure, fully unit testable place so that the calling Tier 0 function can make
        a deterministic decision and surface an actionable error message.

        The verdict is produced in the following order:
          1. A non zero exit code is always a failure.
          2. A recognised failure token wins over a success token, because ntdsutil can emit
             a banner before failing.
          3. The success token 'Password has been set successfully' marks success.
          4. Anything else is treated as a failure, because an unrecognised transcript must
             never be reported as a completed Tier 0 credential change.

        The raw transcript is returned so that the caller can log it, but it is never parsed
        for, nor expected to contain, the password itself.

    .PARAMETER StandardOutput
        The complete text captured from the ntdsutil standard output stream. May be empty
        when the process failed to produce a transcript.

    .PARAMETER StandardError
        The complete text captured from the ntdsutil standard error stream. May be empty
        when the process did not write any diagnostic output.

    .PARAMETER ExitCode
        The process exit code returned by ntdsutil.exe. Any non zero value is treated as an
        unconditional failure regardless of the transcript content.

    .EXAMPLE
        ConvertFrom-PSADNtdsutilOutput -StandardOutput 'Password has been set successfully.' -StandardError '' -ExitCode 0

        Returns a verdict whose Succeeded property is true.

    .EXAMPLE
        $verdict = ConvertFrom-PSADNtdsutilOutput -StandardOutput $raw.StandardOutput -StandardError $raw.StandardError -ExitCode $raw.ExitCode
        if (-not $verdict.Succeeded) { throw $verdict.FailureReason }

        Converts a failed reset into a terminating error carrying a human readable cause.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        Internal helper. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [AllowNull()]
        [System.String]
        $StandardOutput,

        [Parameter(Position = 1)]
        [AllowEmptyString()]
        [AllowNull()]
        [System.String]
        $StandardError = '',

        [Parameter(Position = 2)]
        [System.Int32]
        $ExitCode = 0
    )

    begin
    {
        $successToken = 'Password has been set successfully'

        <#
            Ordered so that the most specific and most actionable diagnosis is matched first.
            Both the localisable English text and the stable HRESULT are matched where one
            exists, so that the parser still works against a non English domain controller.
        #>
        $failureSignature = [ordered]@{
            'Access is denied'            = 'Access was denied by the target domain controller. The account performing the reset must hold Tier 0 rights (Domain Admins or Enterprise Admins) and administrative rights on the target host.'
            '0x80070005'                  = 'Access was denied by the target domain controller (HRESULT 0x80070005). Verify Tier 0 group membership and that the account is not filtered by an RODC Password Replication Policy.'
            'The server is not operational' = 'The target domain controller did not answer the directory bind. Confirm that the DC is online and that LDAP and RPC are reachable from the management host.'
            '0x8007203a'                  = 'The directory server is not operational (HRESULT 0x8007203a). The DSRM reset could not be delivered to the target domain controller.'
            'does not meet the length, complexity' = 'The supplied password was rejected by the password policy applied to the DSRM account on the target domain controller.'
            'password does not meet'      = 'The supplied password was rejected by the password policy applied to the DSRM account on the target domain controller.'
            'Setting password failed'     = 'ntdsutil reported that setting the DSRM password failed. Inspect the captured transcript for the underlying Win32 status.'
            'Directory Service is busy'   = 'The directory service on the target domain controller is busy. Retry the reset once the current maintenance operation has completed.'
            'The parameter is incorrect'  = 'ntdsutil rejected the reset directive. Verify that the resolved server name is a genuine domain controller.'
            'Invalid syntax'              = 'ntdsutil rejected the command syntax. This usually indicates an unexpected ntdsutil build on the management host.'
            'No such object'              = 'The target server object could not be located in the directory. Verify the domain controller name.'
        }
    }

    process
    {
        $outputText = if ($null -eq $StandardOutput) { '' } else { $StandardOutput }
        $errorText = if ($null -eq $StandardError) { '' } else { $StandardError }
        $transcript = ('{0}{1}{2}' -f $outputText, [System.Environment]::NewLine, $errorText)

        $failureReason = $null

        foreach ($signature in $failureSignature.Keys)
        {
            if ($transcript -match [System.Text.RegularExpressions.Regex]::Escape($signature))
            {
                $failureReason = $failureSignature[$signature]
                break
            }
        }

        if ($ExitCode -ne 0)
        {
            $exitCodeReason = 'ntdsutil.exe exited with code {0}.' -f $ExitCode
            $failureReason = if ($null -eq $failureReason) { $exitCodeReason } else { '{0} {1}' -f $exitCodeReason, $failureReason }
        }

        $succeeded = $false

        if ($null -eq $failureReason)
        {
            if ($transcript -match [System.Text.RegularExpressions.Regex]::Escape($successToken))
            {
                $succeeded = $true
            }
            else
            {
                $failureReason = 'ntdsutil did not report a successful password change. The DSRM password must be considered unchanged. Review the captured transcript before retrying.'
            }
        }

        Write-Verbose -Message ('ntdsutil verdict: Succeeded={0}; ExitCode={1}.' -f $succeeded, $ExitCode)

        [PSCustomObject]@{
            Succeeded     = $succeeded
            ExitCode      = $ExitCode
            FailureReason = $failureReason
            Transcript    = $transcript.Trim()
        }
    }
}
