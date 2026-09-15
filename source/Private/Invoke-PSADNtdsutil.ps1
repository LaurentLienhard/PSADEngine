function Invoke-PSADNtdsutil
{
    <#
    .SYNOPSIS
        Drives ntdsutil.exe to reset a DSRM password without exposing the secret.

    .DESCRIPTION
        Launches ntdsutil.exe with redirected standard streams and feeds it the DSRM reset
        dialogue over standard input. This is the only supported non interactive path for a
        DSRM password change and it is implemented here with three deliberate protections.

        First, the password is never placed on the command line. Process command lines are
        readable by any local process through the Win32 API and by any endpoint detection
        agent, and they are routinely captured in Sysmon event ID 1 and in Security event ID
        4688 when command line auditing is enabled. Writing the secret to standard input
        keeps it out of every one of those sinks.

        Second, the password is streamed one UTF-16 code unit at a time directly out of the
        unmanaged BSTR buffer. No managed System.String is ever created, so no immutable
        copy of the DSRM password is left on the garbage collected heap where it could be
        recovered from a process dump. The buffer is zeroed and freed in a finally block.

        Third, both output streams are read asynchronously before standard input is written.
        ntdsutil emits a banner and prompts as soon as it starts, and a synchronous
        ReadToEnd after writing would deadlock as soon as the pipe buffer filled.

        The function returns the raw process result. Interpreting it is the responsibility of
        ConvertFrom-PSADNtdsutilOutput, which keeps the fragile transcript parsing separate
        from this process boundary.

    .PARAMETER ServerName
        The resolved domain controller name to target. This value is written verbatim into
        the ntdsutil directive, so it must already have been sanitised by
        ConvertTo-PSADDomainControllerName. Pass NULL to target the local host.

    .PARAMETER Password
        The new DSRM password as a SecureString. It is streamed to ntdsutil twice, once for
        the prompt and once for the confirmation, and is never converted to a plain string.

    .PARAMETER Credential
        An optional alternate credential to launch ntdsutil.exe under. The SecureString
        password is handed straight to the process start information, so the secret is never
        materialised. When omitted, ntdsutil inherits the access token of the current process.

    .PARAMETER Path
        The full path to ntdsutil.exe. Defaults to the copy in the Windows system directory.
        Override only for testing or for an out of band servicing location.

    .PARAMETER TimeoutSecond
        The maximum number of seconds to wait for ntdsutil to exit before the process is
        killed and a TimeoutException is raised. Defaults to 120 seconds, which accommodates
        a reset delivered across a slow site link.

    .EXAMPLE
        Invoke-PSADNtdsutil -ServerName 'DC01.corp.contoso.com' -Password $secret

        Resets the DSRM password on the named domain controller and returns the raw transcript.

    .EXAMPLE
        $ntdsParam = @{
            ServerName = 'DC02.corp.contoso.com'
            Password   = $secret
            Credential = $tier0Credential
        }
        Invoke-PSADNtdsutil @ntdsParam

        Runs the reset under an alternate Tier 0 account using the splatting pattern.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        Internal helper. Not exported. Windows only.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
        [System.String]
        $ServerName,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNull()]
        [System.Security.SecureString]
        $Password,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path,

        [Parameter()]
        [ValidateRange(5, 3600)]
        [System.Int32]
        $TimeoutSecond = 120
    )

    begin
    {
        $isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
        $bytesPerChar = 2
        $lowWordMask = 0xFFFF
        $millisecondsPerSecond = 1000
        $promptRepetition = 2
    }

    process
    {
        if (-not $isWindowsPlatform)
        {
            throw [System.PlatformNotSupportedException]::new(
                'ntdsutil.exe is a Windows only tool. Run this Tier 0 operation from a Windows Privileged Access Workstation or administrative jump host.')
        }

        $executablePath = if ($PSBoundParameters.ContainsKey('Path'))
        {
            $Path
        }
        else
        {
            Join-Path -Path $env:SystemRoot -ChildPath 'System32\ntdsutil.exe'
        }

        Write-Verbose -Message ("Resolved the ntdsutil.exe executable path to '{0}'." -f $executablePath)

        if (-not (Test-Path -Path $executablePath -PathType Leaf))
        {
            throw [System.IO.FileNotFoundException]::new(
                ("ntdsutil.exe was not found at '{0}'. Install the AD DS and AD LDS Tools feature of Remote Server Administration Tools on this host." -f $executablePath),
                $executablePath)
        }

        $useCredential = ($null -ne $Credential) -and
            ($Credential -ne [System.Management.Automation.PSCredential]::Empty) -and
            (-not [System.String]::IsNullOrWhiteSpace($Credential.UserName))

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $executablePath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.WorkingDirectory = $env:SystemRoot

        if ($useCredential)
        {
            $credentialUser = $Credential.UserName
            $credentialDomain = ''

            if ($credentialUser.Contains('\'))
            {
                $credentialPart = $credentialUser -split '\\', 2
                $credentialDomain = $credentialPart[0]
                $credentialUser = $credentialPart[1]
            }

            $startInfo.UserName = $credentialUser
            $startInfo.Domain = $credentialDomain

            # The SecureString is handed over as is; no plain text copy is created.
            $startInfo.Password = $Credential.Password

            Write-Verbose -Message ("ntdsutil.exe will be launched under the alternate account '{0}'." -f $Credential.UserName)
        }

        $process = $null
        $unmanagedBuffer = [System.IntPtr]::Zero

        try
        {
            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo = $startInfo

            if (-not $process.Start())
            {
                throw [System.InvalidOperationException]::new(
                    'ntdsutil.exe could not be started. No new process was created.')
            }

            Write-Verbose -Message ('ntdsutil.exe started as process {0}. Draining both output pipes asynchronously before any input is written.' -f $process.Id)

            # Start draining both pipes before writing, otherwise ntdsutil deadlocks.
            $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
            $standardErrorTask = $process.StandardError.ReadToEndAsync()

            $inputWriter = $process.StandardInput
            $inputWriter.WriteLine('set dsrm password')
            $inputWriter.WriteLine(('reset password on server {0}' -f $ServerName))

            <#
                Only the fact that the secret is being streamed is narrated. Neither the
                password, nor its length, nor any code unit is written to a stream: the loop
                bounds below are derived from Password.Length precisely so the secret never
                has to be measured anywhere an operator can see it.
            #>
            Write-Verbose -Message ('Streaming the DSRM secret to the ntdsutil standard input for the prompt and its confirmation. The secret is never placed on the command line and never becomes a managed string.')

            $unmanagedBuffer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)

            for ($repetition = 0; $repetition -lt $promptRepetition; $repetition++)
            {
                for ($index = 0; $index -lt $Password.Length; $index++)
                {
                    $codeUnit = [System.Int32][System.Runtime.InteropServices.Marshal]::ReadInt16(
                        $unmanagedBuffer, $index * $bytesPerChar)

                    $inputWriter.Write([System.Char]($codeUnit -band $lowWordMask))
                }

                $inputWriter.Write([System.Environment]::NewLine)
            }

            $inputWriter.Flush()

            $inputWriter.WriteLine('quit')
            $inputWriter.WriteLine('quit')
            $inputWriter.Flush()
            $inputWriter.Close()

            if (-not $process.WaitForExit($TimeoutSecond * $millisecondsPerSecond))
            {
                $process.Kill()

                throw [System.TimeoutException]::new(
                    ("ntdsutil.exe did not exit within {0} seconds while targeting '{1}'. The process was terminated. The DSRM password state on the target is indeterminate and must be verified." -f $TimeoutSecond, $ServerName))
            }

            $standardOutput = $standardOutputTask.GetAwaiter().GetResult()
            $standardError = $standardErrorTask.GetAwaiter().GetResult()

            <#
                The transcript is measured but never echoed. ntdsutil prompts are captured
                verbatim on standard output and, on some builds, the prompt line and the
                typed response can share a buffer, so echoing the transcript to the verbose
                stream would be a plausible secret disclosure path. Interpretation is left to
                ConvertFrom-PSADNtdsutilOutput, which narrates the parsed verdict instead.
            #>
            Write-Verbose -Message ('ntdsutil.exe exited with code {0} after emitting {1} character(s) on standard output and {2} on standard error. The transcript is returned for parsing and is not narrated.' -f $process.ExitCode, $standardOutput.Length, $standardError.Length)

            [PSCustomObject]@{
                ServerName     = $ServerName
                ExitCode       = $process.ExitCode
                StandardOutput = $standardOutput
                StandardError  = $standardError
            }
        }
        catch [System.ComponentModel.Win32Exception]
        {
            throw [System.UnauthorizedAccessException]::new(
                ('ntdsutil.exe could not be launched. When an alternate credential is supplied the account must be able to log on to this host. Detail: {0}' -f $_.Exception.Message),
                $_.Exception)
        }
        finally
        {
            if ($unmanagedBuffer -ne [System.IntPtr]::Zero)
            {
                # Deterministic scrub of the decrypted DSRM password.
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($unmanagedBuffer)
            }

            if ($null -ne $process)
            {
                $process.Dispose()
            }
        }
    }
}
