BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    BeforeAll {
        $script:successTranscript = @'
ntdsutil: set dsrm password
Reset DSRM Administrator Password: reset password on server DC01.corp.contoso.com
Please type password for DS Restore Mode Administrator Account:
Please confirm new password:
Password has been set successfully.
Reset DSRM Administrator Password: quit
ntdsutil: quit
'@
    }

    Describe 'ConvertFrom-PSADNtdsutilOutput' {
        Context 'When ntdsutil reports success' {
            It 'Should return a successful verdict' {
                $result = ConvertFrom-PSADNtdsutilOutput -StandardOutput $script:successTranscript -StandardError '' -ExitCode 0

                $result.Succeeded | Should -BeTrue
                $result.FailureReason | Should -BeNullOrEmpty
            }

            It 'Should preserve the transcript for the audit trail' {
                $result = ConvertFrom-PSADNtdsutilOutput -StandardOutput $script:successTranscript -StandardError '' -ExitCode 0

                $result.Transcript | Should -Match 'reset password on server DC01'
            }
        }

        Context 'When the exit code is non zero' {
            It 'Should fail even when the success token is present' {
                $result = ConvertFrom-PSADNtdsutilOutput -StandardOutput $script:successTranscript -StandardError '' -ExitCode 1

                $result.Succeeded | Should -BeFalse
                $result.FailureReason | Should -Match 'exited with code 1'
            }

            It 'Should report the exit code on the verdict' {
                (ConvertFrom-PSADNtdsutilOutput -StandardOutput '' -StandardError '' -ExitCode 5).ExitCode | Should -Be 5
            }
        }

        Context 'When ntdsutil reports a recognised failure' {
            It 'Should diagnose <Description>' -ForEach @(
                @{
                    Description = 'access denied'
                    Output      = 'Setting password failed. Access is denied.'
                    Match       = 'Access was denied'
                }
                @{
                    Description = 'the access denied HRESULT'
                    Output      = 'Failed with 0x80070005'
                    Match       = 'Access was denied'
                }
                @{
                    Description = 'an unreachable directory server'
                    Output      = 'Error: The server is not operational.'
                    Match       = 'did not answer the directory bind'
                }
                @{
                    Description = 'the not operational HRESULT'
                    Output      = 'ldap error 0x8007203a'
                    Match       = 'not operational'
                }
                @{
                    Description = 'a password policy rejection'
                    Output      = 'The password does not meet the length, complexity, or history requirement'
                    Match       = 'rejected by the password policy'
                }
                @{
                    Description = 'a busy directory service'
                    Output      = 'The Directory Service is busy'
                    Match       = 'is busy'
                }
                @{
                    Description = 'a rejected directive'
                    Output      = 'The parameter is incorrect.'
                    Match       = 'rejected the reset directive'
                }
                @{
                    Description = 'invalid syntax'
                    Output      = 'Invalid syntax.'
                    Match       = 'rejected the command syntax'
                }
                @{
                    Description = 'a missing server object'
                    Output      = 'No such object on the server.'
                    Match       = 'could not be located in the directory'
                }
            ) {
                $result = ConvertFrom-PSADNtdsutilOutput -StandardOutput $Output -StandardError '' -ExitCode 0

                $result.Succeeded | Should -BeFalse
                $result.FailureReason | Should -Match $Match
            }

            It 'Should let a failure signature win over a success token' {
                $mixed = "Password has been set successfully.`r`nAccess is denied."

                $result = ConvertFrom-PSADNtdsutilOutput -StandardOutput $mixed -StandardError '' -ExitCode 0

                $result.Succeeded | Should -BeFalse
            }

            It 'Should inspect the standard error stream as well' {
                $result = ConvertFrom-PSADNtdsutilOutput -StandardOutput '' -StandardError 'Access is denied.' -ExitCode 0

                $result.Succeeded | Should -BeFalse
                $result.FailureReason | Should -Match 'Access was denied'
            }
        }

        Context 'When the transcript is unrecognised' {
            It 'Should fail closed rather than reporting a silent success for <Description>' -ForEach @(
                @{ Description = 'an empty transcript'; Output = '' }
                @{ Description = 'a null transcript'; Output = $null }
                @{ Description = 'only a banner'; Output = 'ntdsutil: quit' }
                @{ Description = 'unrelated noise'; Output = 'something unexpected happened' }
            ) {
                $result = ConvertFrom-PSADNtdsutilOutput -StandardOutput $Output -StandardError '' -ExitCode 0

                $result.Succeeded | Should -BeFalse
                $result.FailureReason | Should -Match 'must be considered unchanged'
            }
        }

        Context 'Parameter handling' {
            It 'Should default StandardError and ExitCode' {
                $result = ConvertFrom-PSADNtdsutilOutput -StandardOutput 'Password has been set successfully.'

                $result.Succeeded | Should -BeTrue
                $result.ExitCode | Should -Be 0
            }

            It 'Should accept a null standard error without throwing' {
                { ConvertFrom-PSADNtdsutilOutput -StandardOutput 'Password has been set successfully.' -StandardError $null } |
                    Should -Not -Throw
            }
        }

        Context 'Operator feedback' {
            It 'Should narrate the parsed verdict and the transcript size' {
                $verdictParam = @{
                    StandardOutput = 'Password has been set successfully.'
                    StandardError  = ''
                    ExitCode       = 0
                }

                $verbose = ConvertFrom-PSADNtdsutilOutput @verdictParam -Verbose 4>&1 | Out-String

                $verbose | Should -Match 'Succeeded=True'
                $verbose | Should -Match 'ExitCode=0'
                $verbose | Should -Match 'success token matched'
                $verbose | Should -Match 'character ntdsutil transcript'
            }

            It 'Should narrate a matched failure signature' {
                $verdictParam = @{
                    StandardOutput = 'Setting password failed. Access is denied.'
                    StandardError  = ''
                    ExitCode       = 0
                }

                $verbose = ConvertFrom-PSADNtdsutilOutput @verdictParam -Verbose 4>&1 | Out-String

                $verbose | Should -Match 'Succeeded=False'
                $verbose | Should -Match 'failure signature matched'
            }

            It 'Should never echo the raw transcript into the narration' {
                <#
                    ntdsutil echoes its prompts on standard output and the captured buffer is
                    not guaranteed to exclude a typed response on every build, so the raw
                    text is returned for deliberate logging and never auto-narrated.
                #>
                $verdictParam = @{
                    StandardOutput = 'Password has been set successfully. TRANSCRIPT-MARKER-VALUE'
                    StandardError  = ''
                    ExitCode       = 0
                }

                $verbose = ConvertFrom-PSADNtdsutilOutput @verdictParam -Verbose 4>&1 |
                    Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } |
                    Out-String

                $verbose | Should -Not -Match 'TRANSCRIPT-MARKER-VALUE'
            }

            It 'Should still return the transcript on the object for deliberate logging' {
                $verdictParam = @{
                    StandardOutput = 'Password has been set successfully. TRANSCRIPT-MARKER-VALUE'
                    StandardError  = ''
                    ExitCode       = 0
                }

                $result = ConvertFrom-PSADNtdsutilOutput @verdictParam

                $result.Transcript | Should -Match 'TRANSCRIPT-MARKER-VALUE'
            }
        }
    }
}
