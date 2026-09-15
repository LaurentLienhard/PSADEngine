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
    }

    Describe 'Write-PSADAuditEvent' {
        Context 'Fail-safe behaviour' {
            It 'Should never throw when the audit sink is unavailable' {
                $auditParam = @{
                    Message   = 'DSRM password reset ATTEMPT. Target: DC01.corp.contoso.com.'
                    EntryType = 'Warning'
                    EventId   = 9000
                    LogName   = 'ThisLogDoesNotExist'
                    Source    = 'PSADEngineUnitTest'
                }

                { Write-PSADAuditEvent @auditParam -WarningAction SilentlyContinue } | Should -Not -Throw
            }

            It 'Should report false when the record could not be written' -Skip:$script:isWindowsPlatform {
                $auditParam = @{
                    Message   = 'DSRM password reset ATTEMPT. Target: DC01.corp.contoso.com.'
                    EntryType = 'Warning'
                    EventId   = 9000
                }

                Write-PSADAuditEvent @auditParam | Should -BeFalse
            }

            It 'Should return a boolean' {
                $auditParam = @{
                    Message   = 'DSRM password reset ATTEMPT. Target: DC01.corp.contoso.com.'
                    EntryType = 'Information'
                    EventId   = 9001
                }

                Write-PSADAuditEvent @auditParam -WarningAction SilentlyContinue | Should -BeOfType [bool]
            }
        }

        Context 'Verbose mirroring' {
            It 'Should always mirror the record to the verbose stream so a trail exists' {
                $auditParam = @{
                    Message   = 'DSRM password reset SUCCESS. Target: DC01.corp.contoso.com.'
                    EntryType = 'Information'
                    EventId   = 9001
                }

                $verbose = Write-PSADAuditEvent @auditParam -Verbose -WarningAction SilentlyContinue 4>&1 |
                    Out-String

                $verbose | Should -Match 'AUDIT Information/9001'
                $verbose | Should -Match 'DC01.corp.contoso.com'
            }
        }

        Context 'Parameter validation' {
            It 'Should reject an empty message because a blank audit record is useless' {
                { Write-PSADAuditEvent -Message '' } | Should -Throw
            }

            It 'Should reject <EntryType> as an entry type' -ForEach @(
                @{ EntryType = 'Critical' }
                @{ EntryType = 'Debug' }
                @{ EntryType = 'Verbose' }
            ) {
                { Write-PSADAuditEvent -Message 'test' -EntryType $EntryType } | Should -Throw
            }

            It 'Should accept <EntryType> as an entry type' -ForEach @(
                @{ EntryType = 'Information' }
                @{ EntryType = 'Warning' }
                @{ EntryType = 'Error' }
            ) {
                { Write-PSADAuditEvent -Message 'test' -EntryType $EntryType -WarningAction SilentlyContinue } |
                    Should -Not -Throw
            }

            It 'Should reject an event identifier outside the event log range' {
                { Write-PSADAuditEvent -Message 'test' -EventId 70000 } | Should -Throw
            }

            It 'Should default to the Application log and the PSADEngine source' {
                $parameters = (Get-Command -Name 'Write-PSADAuditEvent').ScriptBlock.Ast.Body.ParamBlock.Parameters

                $parameters.Where({ $_.Name.VariablePath.UserPath -eq 'LogName' }).DefaultValue.Extent.Text |
                    Should -Be "'Application'"

                $parameters.Where({ $_.Name.VariablePath.UserPath -eq 'Source' }).DefaultValue.Extent.Text |
                    Should -Be "'PSADEngine'"
            }
        }

        Context 'Implementation choices' {
            BeforeAll {
                <#
                    These assertions inspect the abstract syntax tree rather than the raw
                    source text. A regular expression over the source would also match the
                    comment based help, which documents the very constructs being forbidden.
                #>
                $script:ast = (Get-Command -Name 'Write-PSADAuditEvent').ScriptBlock.Ast

                $script:invokedCommand = @(
                    $script:ast.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
                        ForEach-Object -Process { $_.GetCommandName() }
                )

                $script:referencedType = @(
                    $script:ast.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.TypeExpressionAst] }, $true) |
                        ForEach-Object -Process { $_.TypeName.FullName }
                )
            }

            It 'Should not call <CommandName>, which was never ported to PowerShell Core' -ForEach @(
                @{ CommandName = 'Write-EventLog' }
                @{ CommandName = 'New-EventLog' }
                @{ CommandName = 'Limit-EventLog' }
            ) {
                $script:invokedCommand | Should -Not -Contain $CommandName
            }

            It 'Should use the System.Diagnostics.EventLog type directly' {
                $script:referencedType | Should -Contain 'System.Diagnostics.EventLog'
            }

            It 'Should dispose the event log handle in a finally block' {
                $tryWithFinally = @(
                    $script:ast.FindAll(
                        {
                            $args[0] -is [System.Management.Automation.Language.TryStatementAst] -and
                            $null -ne $args[0].Finally
                        }, $true)
                )

                $tryWithFinally.Count | Should -BeGreaterThan 0
                $tryWithFinally[0].Finally.Extent.Text | Should -Match 'Dispose'
            }
        }
    }
}
