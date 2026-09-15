BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force

    $script:isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    BeforeAll {
        $script:isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows

        function script:New-TestSecureString
        {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
            param ([string]$PlainText)

            return (ConvertTo-SecureString -String $PlainText -AsPlainText -Force)
        }

        $script:testPassword = script:New-TestSecureString -PlainText 'Tr0ub4dor-Horse-Battery!'
    }

    Describe 'Invoke-PSADNtdsutil' {
        Context 'Server name sanitisation' {
            It 'Should reject <ServerName> before a process is ever started' -ForEach @(
                @{ ServerName = 'DC01 quit' }
                @{ ServerName = "DC01`nquit" }
                @{ ServerName = 'DC01;calc' }
                @{ ServerName = 'DC01|whoami' }
                @{ ServerName = '-DC01' }
                @{ ServerName = '' }
            ) {
                { Invoke-PSADNtdsutil -ServerName $ServerName -Password $script:testPassword } | Should -Throw
            }

            It 'Should accept a well formed fully qualified name at the validation stage' {
                $validationError = $null

                try
                {
                    $null = Invoke-PSADNtdsutil -ServerName 'DC01.corp.contoso.com' -Password $script:testPassword -Path '/nonexistent/ntdsutil.exe'
                }
                catch
                {
                    $validationError = $_
                }

                # It must fail on the platform or the missing binary, never on the name pattern.
                $validationError.Exception.Message | Should -Not -Match 'ValidatePattern'
            }
        }

        Context 'Parameter contract' {
            It 'Should type Password as SecureString so the secret is never a plain string' {
                (Get-Command -Name 'Invoke-PSADNtdsutil').Parameters['Password'].ParameterType |
                    Should -Be ([System.Security.SecureString])
            }

            It 'Should type Credential as PSCredential' {
                (Get-Command -Name 'Invoke-PSADNtdsutil').Parameters['Credential'].ParameterType |
                    Should -Be ([System.Management.Automation.PSCredential])
            }

            It 'Should reject a null password' {
                { Invoke-PSADNtdsutil -ServerName 'DC01' -Password $null } | Should -Throw
            }

            It 'Should reject an out of range timeout' {
                { Invoke-PSADNtdsutil -ServerName 'DC01' -Password $script:testPassword -TimeoutSecond 1 } | Should -Throw
            }
        }

        Context 'When the platform is not Windows' -Skip:$script:isWindowsPlatform {
            It 'Should throw a PlatformNotSupportedException' {
                $exception = { Invoke-PSADNtdsutil -ServerName 'DC01.corp.contoso.com' -Password $script:testPassword } |
                    Should -Throw -PassThru

                $exception.Exception.GetType().FullName | Should -Be 'System.PlatformNotSupportedException'
            }

            It 'Should name the Privileged Access Workstation requirement in the message' {
                { Invoke-PSADNtdsutil -ServerName 'DC01.corp.contoso.com' -Password $script:testPassword } |
                    Should -Throw -ExpectedMessage '*Privileged Access Workstation*'
            }
        }

        Context 'When ntdsutil.exe is missing' -Skip:(-not $script:isWindowsPlatform) {
            It 'Should throw a FileNotFoundException naming the RSAT feature' {
                $ntdsParam = @{
                    ServerName = 'DC01.corp.contoso.com'
                    Password   = $script:testPassword
                    Path       = 'C:\does-not-exist\ntdsutil.exe'
                }

                { Invoke-PSADNtdsutil @ntdsParam } |
                    Should -Throw -ExpectedMessage '*Remote Server Administration Tools*'
            }
        }

        Context 'Secret hygiene' {
            BeforeAll {
                <#
                    These assertions inspect the abstract syntax tree rather than the raw
                    source text, so that the comment based help, which describes the forbidden
                    constructs, cannot satisfy or break them.
                #>
                $script:ast = (Get-Command -Name 'Invoke-PSADNtdsutil').ScriptBlock.Ast

                $script:invokedMember = @(
                    $script:ast.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
                )

                $script:memberName = @(
                    $script:invokedMember |
                        ForEach-Object -Process { $_.Member.Value }
                )

                $script:assignedProperty = @(
                    $script:ast.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
                        ForEach-Object -Process { $_.Left.Extent.Text }
                )
            }

            It 'Should never place the secret on the process command line' {
                <#
                    Command lines are readable by any local process and are captured by
                    Security event ID 4688 and Sysmon event ID 1.
                #>
                $script:assignedProperty | Should -Not -Contain '$startInfo.Arguments'
            }

            It 'Should redirect standard input so the secret is delivered through a pipe' {
                $script:assignedProperty | Should -Contain '$startInfo.RedirectStandardInput'
            }

            It 'Should zero and free the unmanaged buffer holding the decrypted secret' {
                $script:memberName | Should -Contain 'ZeroFreeBSTR'
            }

            It 'Should not call <MemberName>, which would materialise the secret as a managed string' -ForEach @(
                @{ MemberName = 'PtrToStringBSTR' }
                @{ MemberName = 'PtrToStringUni' }
                @{ MemberName = 'PtrToStringAuto' }
                @{ MemberName = 'SecureStringToCoTaskMemUnicode' }
                @{ MemberName = 'GetNetworkCredential' }
            ) {
                $script:memberName | Should -Not -Contain $MemberName
            }

            It 'Should hand the SecureString straight to the process start information' {
                $script:assignedProperty | Should -Contain '$startInfo.Password'
            }

            It 'Should drain both output pipes before writing to standard input to avoid a deadlock' {
                $readOffset = @(
                    $script:invokedMember |
                        Where-Object -FilterScript { 'ReadToEndAsync' -eq $_.Member.Value } |
                        ForEach-Object -Process { $_.Extent.StartOffset } |
                        Sort-Object
                )

                $writeOffset = @(
                    $script:invokedMember |
                        Where-Object -FilterScript { $_.Member.Value -in @('WriteLine', 'Write') } |
                        ForEach-Object -Process { $_.Extent.StartOffset } |
                        Sort-Object
                )

                $readOffset.Count | Should -Be 2
                $writeOffset.Count | Should -BeGreaterThan 0
                $readOffset[-1] | Should -BeLessThan $writeOffset[0]
            }
        }

        Context 'Operator feedback' {
            BeforeAll {
                <#
                    The narration is asserted against the abstract syntax tree so the checks
                    hold on every platform, including build agents where ntdsutil.exe cannot
                    be launched at all.
                #>
                $script:feedbackAst = (Get-Command -Name 'Invoke-PSADNtdsutil').ScriptBlock.Ast

                $script:narrationCall = @(
                    $script:feedbackAst.FindAll(
                        {
                            $args[0] -is [System.Management.Automation.Language.CommandAst] -and
                            $args[0].GetCommandName() -in @('Write-Verbose', 'Write-Debug', 'Write-Warning', 'Write-Information')
                        }, $true)
                )
            }

            It 'Should narrate at least the path resolution, the process start and the exit' {
                $script:narrationCall.Count | Should -BeGreaterOrEqual 4
            }

            It 'Should narrate the <Topic> step' -ForEach @(
                @{ Topic = 'executable path resolution'; Pattern = 'Resolved the ntdsutil.exe executable path' }
                @{ Topic = 'asynchronous pipe drain'; Pattern = 'Draining both output pipes asynchronously' }
                @{ Topic = 'secret streaming'; Pattern = 'Streaming the DSRM secret' }
                @{ Topic = 'output parsing'; Pattern = 'exited with code' }
            ) {
                $narrationText = ($script:narrationCall | ForEach-Object -Process { $_.Extent.Text }) -join ' '

                $narrationText | Should -Match $Pattern
            }

            It 'Should never reference the secret parameter from any narration call' {
                <#
                    The decisive check: no feedback call may take $Password, the unmanaged
                    buffer or a decrypted code unit as an argument.
                #>
                foreach ($call in $script:narrationCall)
                {
                    $variableUsed = @(
                        $call.FindAll(
                            { $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
                            ForEach-Object -Process { $_.VariablePath.UserPath }
                    )

                    $variableUsed | Should -Not -Contain 'Password'
                    $variableUsed | Should -Not -Contain 'unmanagedBuffer'
                    $variableUsed | Should -Not -Contain 'codeUnit'
                }
            }

            It 'Should narrate the acting account name but never its secret' {
                <#
                    Naming the alternate account is required for a Tier 0 audit trail, so
                    $Credential.UserName is legitimate. Reaching the password behind that
                    credential, directly or through GetNetworkCredential, is not.
                #>
                foreach ($call in $script:narrationCall)
                {
                    $callText = $call.Extent.Text

                    $callText | Should -Not -Match 'Credential\.Password'
                    $callText | Should -Not -Match 'GetNetworkCredential'
                }
            }

            It 'Should never narrate the captured transcript content' {
                <#
                    ntdsutil echoes its prompts, and on some builds the prompt line and the
                    typed response share a buffer, so the transcript is measured and returned
                    but never written to a feedback stream.
                #>
                foreach ($call in $script:narrationCall)
                {
                    $memberAccessed = @(
                        $call.FindAll(
                            { $args[0] -is [System.Management.Automation.Language.MemberExpressionAst] }, $true) |
                            ForEach-Object -Process { $_.Extent.Text }
                    )

                    <#
                        Measuring the transcript is permitted, echoing it is not. Any member
                        access reaching one of the captured streams must terminate in Length.
                    #>
                    $streamAccess = @(
                        $memberAccessed |
                            Where-Object -FilterScript { $_ -match 'standardOutput|standardError|Transcript' }
                    )

                    foreach ($expression in $streamAccess)
                    {
                        $expression | Should -Match '\.Length$'
                    }
                }
            }

            It 'Should narrate the resolved path before failing on a missing executable' -Skip:(-not $script:isWindowsPlatform) {
                $missingParam = @{
                    ServerName = 'DC01'
                    Password   = (script:New-TestSecureString -PlainText 'Str0ng-Enough-Pass!')
                    Path       = 'C:\Windows\System32\ntdsutil-does-not-exist.exe'
                }

                $verbose = { Invoke-PSADNtdsutil @missingParam -Verbose 4>&1 } | Should -Throw -PassThru

                $verbose | Should -Not -BeNullOrEmpty
            }
        }
    }
}
