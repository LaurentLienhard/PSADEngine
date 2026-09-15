function Write-PSADAuditEvent
{
    <#
    .SYNOPSIS
        Writes a Tier 0 audit record to the Windows event log without ever throwing.

    .DESCRIPTION
        Emits a structured audit record describing a privileged directory operation. The
        function is intentionally fail-safe: an audit sink that is unavailable must never
        abort, mask, or partially complete a Tier 0 change, so every failure is downgraded
        to a warning and reported through the return value instead.

        The .NET System.Diagnostics.EventLog API is used rather than the Write-EventLog
        cmdlet because the event log cmdlets were never ported to PowerShell Core, whereas
        the underlying type is available on Windows in both Windows PowerShell 5.1 and
        PowerShell 7 or later.

        The message is always mirrored to the verbose stream so that a transcript exists even
        on a management host where the event source cannot be registered, and so that the
        audit trail is visible during pipeline runs on non Windows platforms.

        SECURITY: callers must never pass secret material in the Message parameter. Nothing
        in this function redacts its input; the redaction contract belongs to the caller.

    .PARAMETER Message
        The audit text to record. Must describe who performed the action, against which
        target, and with which outcome. Must never contain credential material.

    .PARAMETER EntryType
        The severity of the audit record. Accepts Information, Warning or Error and maps
        directly onto the System.Diagnostics.EventLogEntryType enumeration.

    .PARAMETER EventId
        The numeric event identifier to stamp on the record so that a SIEM correlation rule
        can key on it. Must fall within the 1 to 65535 range accepted by the event log API.

    .PARAMETER LogName
        The name of the Windows event log that receives the record. Defaults to Application,
        which requires no custom channel provisioning on a domain controller.

    .PARAMETER Source
        The event source name registered under the target log. Defaults to PSADEngine and is
        created on first use when the caller holds sufficient local rights.

    .EXAMPLE
        Write-PSADAuditEvent -Message 'DSRM password reset attempted on DC01.' -EntryType Information -EventId 9000

        Records a Tier 0 attempt in the Application log under the PSADEngine source.

    .EXAMPLE
        $auditParam = @{
            Message   = 'DSRM password reset failed on DC02.'
            EntryType = 'Error'
            EventId   = 9002
        }
        Write-PSADAuditEvent @auditParam

        Records a failure using the splatting pattern used throughout this module.

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
        $Message,

        [Parameter(Position = 1)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [System.String]
        $EntryType = 'Information',

        [Parameter(Position = 2)]
        [ValidateRange(1, 65535)]
        [System.Int32]
        $EventId = 9000,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $LogName = 'Application',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Source = 'PSADEngine'
    )

    begin
    {
        $isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
    }

    process
    {
        # The verbose mirror is unconditional so an audit trail always exists.
        Write-Verbose -Message ('[AUDIT {0}/{1}] {2}' -f $EntryType, $EventId, $Message)

        if (-not $isWindowsPlatform)
        {
            Write-Verbose -Message 'The Windows event log is unavailable on this platform. The audit record was written to the verbose stream only.'
            return $false
        }

        $eventLog = $null

        try
        {
            if (-not [System.Diagnostics.EventLog]::SourceExists($Source))
            {
                Write-Verbose -Message ("Registering the event source '{0}' in the '{1}' log." -f $Source, $LogName)
                [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
            }

            $eventLog = [System.Diagnostics.EventLog]::new($LogName)
            $eventLog.Source = $Source
            $eventLog.WriteEntry($Message, [System.Diagnostics.EventLogEntryType]$EntryType, $EventId)

            return $true
        }
        catch [System.Security.SecurityException]
        {
            Write-Warning -Message ("The audit record could not be written because the current account lacks rights on the '{0}' log or on the event source registry key. Run the operation from a Privileged Access Workstation with local administrative rights. Detail: {1}" -f $LogName, $_.Exception.Message)
        }
        catch [System.InvalidOperationException]
        {
            Write-Warning -Message ("The audit record could not be written because the event source '{0}' is not usable in the '{1}' log. Detail: {2}" -f $Source, $LogName, $_.Exception.Message)
        }
        catch [System.Exception]
        {
            Write-Warning -Message ('The audit record could not be written. The Tier 0 operation itself was not affected. Detail: {0}' -f $_.Exception.Message)
        }
        finally
        {
            if ($null -ne $eventLog)
            {
                $eventLog.Dispose()
            }
        }

        return $false
    }
}
