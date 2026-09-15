function Set-PSADDsrmPassword
{
    <#
    .SYNOPSIS
        Resets the Directory Services Restore Mode administrator password on one or more
        domain controllers.

    .DESCRIPTION
        Performs a governed reset of the Directory Services Restore Mode (DSRM) password on
        a domain controller. The DSRM account is the local Administrator of the SAM database
        that exists on every domain controller and is used when the directory service cannot
        start. It is a genuine Tier 0 break-glass credential: it survives an Active Directory
        forest compromise, it is not subject to domain password policy, and a stale or shared
        DSRM password is a standing persistence and lateral movement opportunity. Microsoft
        guidance is to rotate it per domain controller on a defined cadence and to store each
        value individually in a privileged secret store.

        The function applies the following controls, in order, and refuses to continue if any
        of them fails:

          1. Password policy gate. The candidate password is validated once for the whole
             batch against a minimum length of 14 characters, at least three of the four
             character categories, and the absence of control characters. Nothing is attempted
             against any domain controller when the policy is not met.

          2. Tier 0 privilege gate. The transitive group membership of the caller, or of the
             supplied credential, is evaluated for Domain Admins, Enterprise Admins or Schema
             Admins by well known relative identifier rather than by localisable group name.
             The evaluation happens once and is cached for the entire batch.

          3. Existence check. The resolved server name must appear in the domain controller
             inventory of the target domain, so that a typo cannot silently target a member
             server or a decommissioned host.

          4. Reachability check. A bounded TCP probe against LDAP port 389 confirms the
             domain controller is answering. ICMP is not used because echo traffic is
             routinely blocked in Zero Trust networks.

          5. Confirmation. ConfirmImpact is High, so an explicit confirmation is required
             unless Force is supplied or Confirm is explicitly set to false.

          6. Audit. An attempt record is written to the Windows event log immediately before
             the change, followed by a success or failure record. Audit sink failures are
             downgraded to warnings and never abort or mask the Tier 0 operation itself.

        The password is handled as a SecureString end to end. It is streamed to ntdsutil.exe
        over standard input one UTF-16 code unit at a time directly from unmanaged memory, so
        it never appears on a process command line, never reaches Security event ID 4688 or
        Sysmon event ID 1, and never exists as a managed string on the garbage collected heap.
        The password is never written to the output, verbose, debug, warning or error streams
        and never reaches the event log.

        Failures are reported per domain controller in the returned object rather than
        aborting the batch, so that one unreachable domain controller cannot leave the
        remaining ones with a stale credential. A non terminating error is also emitted for
        each failure so that existing error handling and transcript logging still observe it.

        OPERATOR FEEDBACK. Every gate narrates its progress on the verbose stream and the
        batch reports on the progress stream, so that a long Tier 0 rotation is observable
        while it runs rather than only in the returned report. Result objects are streamed
        one per domain controller as each completes and are never buffered, so a downstream
        pipeline stage sees each outcome in real time. See the AnalysisLevel parameter to
        control how much narration is produced.

    .PARAMETER Identity
        The domain controller to target. Accepts a distinguished name such as
        'CN=DC01,OU=Domain Controllers,DC=corp,DC=contoso,DC=com', an NTDS Settings
        distinguished name, a NetBIOS name such as 'DC01', a computer account name such as
        'DC01$', or a fully qualified name such as 'DC01.corp.contoso.com'. Accepts pipeline
        input by value and by property name, including from Get-PSADDomainController.

    .PARAMETER NewPassword
        The new DSRM administrator password supplied as a SecureString. Must be at least 14
        characters long, must use at least three of the four character categories, and must
        contain no control character. Retrieve it from a secret store such as
        Microsoft.PowerShell.SecretManagement or Azure Key Vault; never construct it from a
        literal in a script.

    .PARAMETER Credential
        An optional alternate credential holding Tier 0 rights. When supplied, the transitive
        group membership of that account is evaluated over LDAP instead of the current access
        token, and ntdsutil.exe is launched under that account. When omitted, the access token
        of the current process is used, which is the correct behaviour for an interactive
        Privileged Access Workstation session.

    .PARAMETER Force
        Suppresses the confirmation prompt that ConfirmImpact High would otherwise raise.
        Intended for scheduled rotation running under a non interactive Tier 0 service
        identity. An explicit Confirm always wins over Force. Force never bypasses the
        password policy gate, the Tier 0 privilege gate or the auditing.

    .PARAMETER AnalysisLevel
        Controls how much operator feedback the function produces. Defaults to Thorough.

          Thorough - The default and the historical behaviour. Every gate narrates on the
                     verbose stream when the caller asks for verbose output, and the batch
                     reports on the progress stream.

          Quick    - Suppresses the informational narration and the progress bar for this
                     invocation, including narration produced by the internal helpers, so
                     that only errors and warnings reach the host. Intended for scheduled
                     rotation where a transcript would otherwise be dominated by narration.

        SECURITY: AnalysisLevel governs operator feedback only. It never suppresses the
        Windows event log audit trail, never suppresses a non terminating error, and never
        relaxes the password policy gate, the Tier 0 privilege gate, the existence check,
        the reachability check or the confirmation prompt. Quick deliberately overrides an
        explicit Verbose supplied on the same invocation, because 'only errors' is the whole
        contract of that value.

    .EXAMPLE
        $secret = Read-Host -Prompt 'New DSRM password' -AsSecureString
        Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $secret

        Resets the DSRM password on a single domain controller after an interactive
        confirmation prompt.

    .EXAMPLE
        $dsrmParam = @{
            Identity    = 'CN=DC02,OU=Domain Controllers,DC=corp,DC=contoso,DC=com'
            NewPassword = Get-Secret -Name 'DSRM-DC02' -Vault 'Tier0Vault'
            Credential  = $tier0Credential
            Force       = $true
        }
        Set-PSADDsrmPassword @dsrmParam

        Rotates the DSRM password non interactively under an alternate Tier 0 account, taking
        the per domain controller secret from a vault.

    .EXAMPLE
        Get-PSADDomainController |
            Where-Object -FilterScript { $_.IsReachable } |
            Set-PSADDsrmPassword -NewPassword $secret -WhatIf

        Produces a dry-run report for every reachable domain controller. Each result is
        returned with a Skipped status and nothing is changed.

    .EXAMPLE
        $report = 'DC01', 'DC02', 'DC03' |
            Set-PSADDsrmPassword -NewPassword $secret -Force -Verbose
        $report | Where-Object -FilterScript { $_.Status -ne 'Success' }

        Rotates a batch and then isolates the domain controllers that still hold the previous
        DSRM password. The Tier 0 privilege evaluation runs once for the whole batch.

    .EXAMPLE
        $dsrmParam = @{
            NewPassword   = Get-Secret -Name 'DSRM-Rotation' -Vault 'Tier0Vault'
            Force         = $true
            AnalysisLevel = 'Quick'
        }
        Get-PSADDomainController | Set-PSADDsrmPassword @dsrmParam

        Runs an unattended rotation that reports only failures, which keeps a scheduled task
        transcript small while leaving the Windows event log audit trail untouched.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        Author        : LIENHARD Laurent
        Tier          : 0 (control plane)
        Requires      : Windows, ntdsutil.exe from the AD DS and AD LDS Tools RSAT feature,
                        and Domain Admins, Enterprise Admins or Schema Admins membership.
        Impact        : Changes a break-glass credential. The previous DSRM password stops
                        working immediately. Record the new value in a privileged secret
                        store before running this function, not after.
        Rollback      : There is no rollback. Re-run the function with the previous password
                        to restore it, which requires that the previous value is still known.
        Alternative   : 'ntdsutil "set dsrm password" "sync from domain account <account>"'
                        binds the DSRM password to a domain account instead. That approach
                        avoids handling a secret at all but couples a Tier 0 break-glass
                        credential to an account that lives in the directory it is meant to
                        recover, so it is not used here.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('ComputerName', 'Name', 'DistinguishedName', 'HostName')]
        [System.String]
        $Identity,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNull()]
        [System.Security.SecureString]
        $NewPassword,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force,

        [Parameter()]
        [ValidateSet('Quick', 'Thorough')]
        [System.String]
        $AnalysisLevel = 'Thorough'
    )

    begin
    {
        <#
            Capture the caller's error preference before raising the local one to Stop.
            The local Stop preference makes every cmdlet called inside the try block fail
            fast, while per domain controller failures are still reported back to the caller
            using the preference they actually asked for. Hard coding Continue here would
            silently ignore an -ErrorAction supplied by the caller.
        #>
        $callerErrorAction = if ($PSBoundParameters.ContainsKey('ErrorAction'))
        {
            $PSBoundParameters['ErrorAction']
        }
        else
        {
            $ErrorActionPreference
        }

        $ErrorActionPreference = 'Stop'

        <#
            Quick lowers the verbose and progress preferences for this function scope only.
            Because begin, process and end share one scope and child scopes inherit
            preference variables, this single assignment also silences the narration emitted
            by the private helpers without threading a Verbose argument through every splat.
            The audit trail, the warning stream and the error stream are untouched.
        #>
        if ('Quick' -eq $AnalysisLevel)
        {
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        }

        # Correlation identifiers for SIEM rules. Keep these stable across releases.
        $auditEventId = @{
            Attempt = 9000
            Success = 9001
            Failure = 9002
            Denied  = 9003
        }

        $minimumPasswordLength = 14
        $minimumPasswordCategory = 3
        $ldapPort = 389
        $connectivityTimeoutMillisecond = 2000

        $progressActivity = 'Resetting DSRM passwords'
        $progressId = 1

        <#
            Result objects are streamed, never buffered, so that a downstream pipeline stage
            can act on each domain controller as it completes and so that a forest wide batch
            does not grow an unbounded list in memory. Only the three counters survive the
            batch, purely to produce the closing summary.
        #>
        $processedCount = 0
        $successCount = 0
        $failedCount = 0
        $skippedCount = 0

        <#
            The batch size is only knowable when the function was not placed in a pipeline.
            With pipeline input the total is genuinely unknown until the input is exhausted,
            so an indeterminate progress bar and a running count are reported rather than a
            fabricated percentage.
        #>
        $expectedTotal = if ($MyInvocation.ExpectingInput) { 0 } else { 1 }

        $useCredential = $PSBoundParameters.ContainsKey('Credential')

        $performedBy = if ($useCredential) { $Credential.UserName } else { [System.Environment]::UserName }

        if ($Force.IsPresent -and -not $PSBoundParameters.ContainsKey('Confirm'))
        {
            $ConfirmPreference = 'None'
            Write-Verbose -Message ("Force was supplied. ConfirmPreference is '{0}' for this invocation. The privilege, policy and audit gates still apply." -f $ConfirmPreference)
        }

        # --- Gate 1: password policy, evaluated once for the whole batch. ---
        Write-Verbose -Message ('Validating password complexity against the Tier 0 policy (minimum {0} characters, minimum {1} character categories, no control characters).' -f $minimumPasswordLength, $minimumPasswordCategory)

        $complexityParam = @{
            Password        = $NewPassword
            MinimumLength   = $minimumPasswordLength
            MinimumCategory = $minimumPasswordCategory
        }

        $complexity = Test-PSADDsrmPasswordComplexity @complexityParam

        if (-not $complexity.IsValid)
        {
            throw [System.ArgumentException]::new(
                ('The supplied DSRM password does not satisfy the Tier 0 password policy: {0}' -f ($complexity.FailureReason -join ' ')),
                'NewPassword')
        }

        Write-Verbose -Message ('The candidate DSRM password satisfies the Tier 0 policy ({0} characters, {1} character categories).' -f $complexity.Length, $complexity.CategoryCount)

        # --- Gate 2: Tier 0 privilege, evaluated once and cached for the whole batch. ---
        Write-Verbose -Message ("Checking Tier 0 privileges for '{0}' using the {1}." -f $performedBy, $(if ($useCredential) { 'transitive tokenGroups of the supplied credential' } else { 'access token of the current process' }))

        $tokenParam = @{}

        if ($useCredential)
        {
            $tokenParam['Credential'] = $Credential
        }

        try
        {
            $securityIdentifier = Get-PSADTokenGroupSid @tokenParam
        }
        catch [System.PlatformNotSupportedException]
        {
            throw
        }
        catch [System.Exception]
        {
            throw [System.UnauthorizedAccessException]::new(
                ('The Tier 0 privilege of {0} could not be established, so no DSRM password reset was attempted: {1}' -f $performedBy, $_.Exception.Message),
                $_.Exception)
        }

        $privilege = Test-PSADTier0Privilege -SecurityIdentifier $securityIdentifier

        if (-not $privilege.IsTier0)
        {
            Write-Verbose -Message 'Writing audit event for the refused Tier 0 operation.'

            $deniedParam = @{
                Message   = ('DSRM password reset DENIED. Principal: {0}. Reason: the principal holds none of Domain Admins, Enterprise Admins or Schema Admins. Evaluated {1} security identifiers.' -f $performedBy, $privilege.EvaluatedSidCount)
                EntryType = 'Error'
                EventId   = $auditEventId.Denied
            }

            $null = Write-PSADAuditEvent @deniedParam

            throw [System.UnauthorizedAccessException]::new(
                ("The principal '{0}' does not hold Tier 0 privileges. Resetting a DSRM password requires membership of Domain Admins, Enterprise Admins or Schema Admins." -f $performedBy))
        }

        Write-Verbose -Message ("Tier 0 privilege confirmed for '{0}' through the role '{1}'." -f $performedBy, $privilege.MatchedRole)
    }

    process
    {
        $timestamp = [System.DateTime]::UtcNow
        $serverName = $Identity
        $status = 'Failed'
        $notes = [System.Collections.Generic.List[System.String]]::new()
        $failureRecord = $null
        $failureCategory = $null
        $contextMessage = $null

        $processedCount++

        $progressParam = @{
            Activity = $progressActivity
            Status   = ('Processing {0}' -f $Identity)
            Id       = $progressId
        }

        if ($expectedTotal -gt 0)
        {
            $progressParam['PercentComplete'] = [System.Math]::Min(100, [System.Int32](($processedCount / $expectedTotal) * 100))
        }
        else
        {
            # -1 renders an indeterminate bar, which is honest when the batch size is unknown.
            $progressParam['PercentComplete'] = -1
            $progressParam['CurrentOperation'] = ('Domain controller {0} of the pipeline batch.' -f $processedCount)
        }

        Write-Progress @progressParam

        try
        {
            # --- Resolve and sanitise the target name before it reaches ntdsutil. ---
            Write-Verbose -Message ("Verifying domain controller existence for '{0}'." -f $Identity)

            $serverName = ConvertTo-PSADDomainControllerName -Identity $Identity

            # --- Gate 3: the target must be a known domain controller. ---
            $domainHint = Get-PSADDomainHintFromIdentity -Identity $Identity -ServerName $serverName

            $inventoryParam = @{
                WhatIf      = $false
                Confirm     = $false
                ErrorAction = 'Stop'
            }

            if (-not [System.String]::IsNullOrWhiteSpace($domainHint))
            {
                $inventoryParam['DomainName'] = $domainHint
            }

            $knownController = Get-PSADDomainController @inventoryParam

            $shortName = ($serverName -split '\.')[0]

            $matchedController = @($knownController).Where({
                    $null -ne $_ -and (
                        $_.Name -eq $serverName -or
                        ($_.Name -split '\.')[0] -eq $shortName
                    )
                }, 'First')

            if (0 -eq $matchedController.Count)
            {
                throw [System.Management.Automation.ItemNotFoundException]::new(
                    ("'{0}' is not a domain controller of the target domain. Verify the identity; a DSRM reset must never be aimed at a member server." -f $serverName))
            }

            # Adopt the canonical fully qualified name reported by the directory.
            $serverName = $matchedController[0].Name
            $notes.Add(('Resolved to the domain controller {0}.' -f $serverName))

            Write-Verbose -Message ("Domain controller existence confirmed. '{0}' resolved to the canonical name '{1}'." -f $Identity, $serverName)

            # --- Gate 4: reachability. ---
            Write-Verbose -Message ('Testing LDAP connectivity on {0} (port {1}, {2} ms budget).' -f $serverName, $ldapPort, $connectivityTimeoutMillisecond)

            $connectivityParam = @{
                ComputerName        = $serverName
                Port                = $ldapPort
                TimeoutMilliseconds = $connectivityTimeoutMillisecond
            }

            if (-not (Test-PSADLdapConnectivity @connectivityParam))
            {
                throw [System.InvalidOperationException]::new(
                    ("The domain controller '{0}' did not answer on LDAP port {1} within {2} ms. The DSRM password was not changed." -f $serverName, $ldapPort, $connectivityTimeoutMillisecond))
            }

            Write-Verbose -Message ("LDAP connectivity confirmed on '{0}'." -f $serverName)

            # --- Gate 5: confirmation. ---
            $shouldProcessAction = 'Reset the Directory Services Restore Mode administrator password'
            $shouldProcessTarget = "Domain Controller '$serverName'"

            if (-not $PSCmdlet.ShouldProcess($shouldProcessTarget, $shouldProcessAction))
            {
                $status = 'Skipped'
                $notes.Add('The reset was not performed because WhatIf was supplied or the confirmation prompt was declined.')

                Write-Verbose -Message ("The reset of '{0}' was skipped. WhatIf was supplied or the confirmation prompt was declined." -f $serverName)
            }
            else
            {
                # --- Gate 6: audit the attempt before the change, not after. ---
                Write-Verbose -Message ("Writing audit event {0} (ATTEMPT) for '{1}' before the change is delivered." -f $auditEventId.Attempt, $serverName)

                $attemptParam = @{
                    Message   = ('DSRM password reset ATTEMPT. Target: {0}. Principal: {1}. Role: {2}. Started (UTC): {3:o}.' -f $serverName, $performedBy, $privilege.MatchedRole, $timestamp)
                    EntryType = 'Warning'
                    EventId   = $auditEventId.Attempt
                }

                $null = Write-PSADAuditEvent @attemptParam

                $ntdsutilParam = @{
                    ServerName = $serverName
                    Password   = $NewPassword
                }

                if ($useCredential)
                {
                    $ntdsutilParam['Credential'] = $Credential
                }

                Write-Verbose -Message ("Resetting DSRM password via ntdsutil.exe on '{0}'." -f $serverName)

                $rawResult = Invoke-PSADNtdsutil @ntdsutilParam

                $verdictParam = @{
                    StandardOutput = $rawResult.StandardOutput
                    StandardError  = $rawResult.StandardError
                    ExitCode       = $rawResult.ExitCode
                }

                $verdict = ConvertFrom-PSADNtdsutilOutput @verdictParam

                if (-not $verdict.Succeeded)
                {
                    throw [System.InvalidOperationException]::new($verdict.FailureReason)
                }

                $status = 'Success'
                $notes.Add('The DSRM administrator password was reset successfully. Record the new value in the privileged secret store.')

                Write-Verbose -Message ("The DSRM administrator password was reset successfully on '{0}'." -f $serverName)
            }
        }
        <#
            Each catch clause records the error record and a context specific message, then
            defers the shared reporting to the finally block. That keeps one failure handling
            body while still giving every exception category its own operator facing
            sentence, and it guarantees the per domain controller result object is emitted no
            matter which clause fired.

            DESIGN NOTE - why some categories are matched at runtime instead of by a typed
            catch clause. PowerShell resolves a catch clause type only when the clause is
            actually evaluated, and an unresolvable type raises
            'InvalidOperation: Unable to find type' which REPLACES the real exception and
            destroys the diagnosis. This module intentionally has no dependency on the
            ActiveDirectory RSAT module (Get-PSADDomainController uses
            System.DirectoryServices.ActiveDirectory and RequiredModules is empty), so
            Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException is never
            guaranteed to be loadable here; the same applies to
            System.DirectoryServices.Protocols.LdapException on a host where that assembly
            has not been loaded. Both are therefore classified by full type name at runtime
            inside Resolve-PSADDsrmFailureDetail, which walks the whole inner exception chain
            and yields the identical LdapConnectivity and TargetNotFound categories without
            any risk of masking the real fault. Only types guaranteed to be resolvable are
            declared as typed catch clauses below.
        #>
        catch [System.Management.Automation.ItemNotFoundException]
        {
            $failureRecord = $_
            $contextMessage = ("Domain controller lookup failed: '{0}' was not found in the domain controller inventory of the target domain." -f $serverName)
        }
        catch [System.UnauthorizedAccessException]
        {
            $failureRecord = $_
            $contextMessage = ("Permission denied while resetting the DSRM password on '{0}'. The acting principal was accepted by the Tier 0 gate but was refused by the target." -f $serverName)
        }
        catch [System.Net.Sockets.SocketException]
        {
            $failureRecord = $_
            $contextMessage = ("TCP connectivity to '{0}' failed at the socket layer. The DSRM password was not changed." -f $serverName)
        }
        catch [System.TimeoutException]
        {
            $failureRecord = $_
            $contextMessage = ("The operation against '{0}' exceeded its time budget. The DSRM password state on that domain controller is INDETERMINATE and must be verified." -f $serverName)
        }
        catch [System.Exception]
        {
            $failureRecord = $_
            $contextMessage = $null
        }
        finally
        {
            if ($null -ne $failureRecord)
            {
                $status = 'Failed'

                $diagnosis = Resolve-PSADDsrmFailureDetail -ErrorRecord $failureRecord
                $failureCategory = $diagnosis.Category

                if (-not [System.String]::IsNullOrWhiteSpace($contextMessage))
                {
                    $notes.Add($contextMessage)
                }

                $notes.Add($diagnosis.Detail)
                $notes.Add($diagnosis.Remediation)
            }

            if ('Skipped' -ne $status)
            {
                Write-Verbose -Message ('Writing audit event {0} ({1}) for {2}.' -f $(if ('Success' -eq $status) { $auditEventId.Success } else { $auditEventId.Failure }), $status.ToUpperInvariant(), $serverName)

                $outcomeParam = @{
                    Message   = ('DSRM password reset {0}. Target: {1}. Principal: {2}. Completed (UTC): {3:o}. Detail: {4}' -f $status.ToUpperInvariant(), $serverName, $performedBy, [System.DateTime]::UtcNow, ($notes -join ' '))
                    EntryType = $(if ('Success' -eq $status) { 'Information' } else { 'Error' })
                    EventId   = $(if ('Success' -eq $status) { $auditEventId.Success } else { $auditEventId.Failure })
                }

                $null = Write-PSADAuditEvent @outcomeParam
            }

            switch ($status)
            {
                'Success' { $successCount++ }
                'Skipped' { $skippedCount++ }
                default { $failedCount++ }
            }

            # Stream per domain controller so a long Tier 0 batch reports as it progresses.
            [PSCustomObject]@{
                ComputerName    = $serverName
                Status          = $status
                Timestamp       = $timestamp
                Notes           = $notes.ToArray()
                Identity        = $Identity
                PerformedBy     = $performedBy
                FailureCategory = $failureCategory
                ErrorRecord     = $failureRecord
            }

            <#
                The non terminating error is raised last so that the result object above has
                already been emitted. An -ErrorAction Stop supplied by the caller therefore
                still terminates the batch, but the operator can see exactly which domain
                controller halted it. Nothing is in flight at this point because the failure
                was already caught, so raising here cannot mask an earlier exception.
            #>
            if ($null -ne $failureRecord)
            {
                $writeErrorParam = @{
                    Message     = ("The DSRM password reset failed for '{0}' [{1}]: {2} Remediation: {3}" -f $serverName, $diagnosis.Category, $diagnosis.Detail, $diagnosis.Remediation)
                    ErrorAction = $callerErrorAction
                }

                Write-Error @writeErrorParam
            }
        }
    }

    end
    {
        Write-Progress -Activity $progressActivity -Id $progressId -Completed

        Write-Verbose -Message ('DSRM rotation batch complete. Processed: {0}. Success: {1}. Failed: {2}. Skipped: {3}.' -f $processedCount, $successCount, $failedCount, $skippedCount)
    }
}
