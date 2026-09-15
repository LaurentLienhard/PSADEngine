BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    BeforeAll {
        function script:New-TestErrorRecord
        {
            param ([System.Exception]$Exception)

            return [System.Management.Automation.ErrorRecord]::new(
                $Exception, 'TestError', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
        }
    }

    Describe 'Resolve-PSADDsrmFailureDetail' {
        Context 'When classifying a known exception type' {
            It 'Should classify <TypeName> as <Category>' -ForEach @(
                @{ TypeName = 'System.UnauthorizedAccessException'; Category = 'Authorization' }
                @{ TypeName = 'System.Management.Automation.ItemNotFoundException'; Category = 'TargetNotFound' }
                @{ TypeName = 'System.InvalidOperationException'; Category = 'OperationFailed' }
                @{ TypeName = 'System.TimeoutException'; Category = 'Timeout' }
                @{ TypeName = 'System.IO.FileNotFoundException'; Category = 'MissingTooling' }
                @{ TypeName = 'System.PlatformNotSupportedException'; Category = 'UnsupportedPlatform' }
                @{ TypeName = 'System.ArgumentException'; Category = 'InvalidInput' }
            ) {
                $exception = (New-Object -TypeName $TypeName -ArgumentList 'test message')
                $errorRecord = script:New-TestErrorRecord -Exception $exception

                $result = Resolve-PSADDsrmFailureDetail -ErrorRecord $errorRecord

                $result.Category | Should -Be $Category
                $result.Remediation | Should -Not -BeNullOrEmpty
            }
        }

        Context 'When the exception type is unknown' {
            It 'Should fall back to the unclassified diagnosis' {
                $errorRecord = script:New-TestErrorRecord -Exception ([System.FormatException]::new('unexpected'))

                $result = Resolve-PSADDsrmFailureDetail -ErrorRecord $errorRecord

                $result.Category | Should -Be 'Unclassified'
                $result.Detail | Should -Be 'unexpected'
            }
        }

        Context 'When the exception carries an inner exception chain' {
            BeforeAll {
                $script:innerMost = [System.ComponentModel.Win32Exception]::new('Access is denied')
                $script:middle = [System.InvalidOperationException]::new('bind failed', $script:innerMost)
                $script:outer = [System.UnauthorizedAccessException]::new('privilege evaluation failed', $script:middle)
            }

            It 'Should flatten every message in the chain so the root cause is visible' {
                $result = Resolve-PSADDsrmFailureDetail -ErrorRecord (script:New-TestErrorRecord -Exception $script:outer)

                $result.Detail | Should -Be 'privilege evaluation failed --> bind failed --> Access is denied'
            }

            It 'Should record the full type chain' {
                $result = Resolve-PSADDsrmFailureDetail -ErrorRecord (script:New-TestErrorRecord -Exception $script:outer)

                $result.ExceptionType.Count | Should -Be 3
                $result.ExceptionType[0] | Should -Be 'System.UnauthorizedAccessException'
                $result.ExceptionType[2] | Should -Be 'System.ComponentModel.Win32Exception'
            }

            It 'Should classify on the outermost recognised type' {
                $result = Resolve-PSADDsrmFailureDetail -ErrorRecord (script:New-TestErrorRecord -Exception $script:outer)

                $result.Category | Should -Be 'Authorization'
            }

            It 'Should walk inwards when the outermost type is unrecognised' {
                $wrapped = [System.FormatException]::new('wrapper', [System.TimeoutException]::new('timed out'))

                $result = Resolve-PSADDsrmFailureDetail -ErrorRecord (script:New-TestErrorRecord -Exception $wrapped)

                $result.Category | Should -Be 'Timeout'
            }
        }

        Context 'Parameter validation' {
            It 'Should reject a null error record' {
                { Resolve-PSADDsrmFailureDetail -ErrorRecord $null } | Should -Throw
            }

            It 'Should accept an error record over the pipeline' {
                $result = script:New-TestErrorRecord -Exception ([System.TimeoutException]::new('x')) |
                    Resolve-PSADDsrmFailureDetail

                $result.Category | Should -Be 'Timeout'
            }
        }

        Context 'Directory exception types classified by name at runtime' {
            BeforeAll {
                <#
                    These types are not loadable on every host and this module deliberately
                    takes no dependency on the ActiveDirectory RSAT module, which is exactly
                    why the resolver matches on the full type NAME instead of declaring a
                    typed catch clause. A stub carrying the identical full name is compiled
                    when the genuine type is absent so the contract is testable everywhere.
                #>
                function script:Confirm-TestExceptionType
                {
                    param ([string]$FullName, [string]$Namespace, [string]$ClassName)

                    if ($FullName -as [type])
                    {
                        return
                    }

                    Add-Type -ErrorAction Stop -TypeDefinition @"
namespace $Namespace
{
    public class $ClassName : System.Exception
    {
        public $ClassName(string message) : base(message) { }
    }
}
"@
                }

                script:Confirm-TestExceptionType -FullName 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException' -Namespace 'Microsoft.ActiveDirectory.Management' -ClassName 'ADIdentityNotFoundException'
                script:Confirm-TestExceptionType -FullName 'Microsoft.ActiveDirectory.Management.ADServerDownException' -Namespace 'Microsoft.ActiveDirectory.Management' -ClassName 'ADServerDownException'
                script:Confirm-TestExceptionType -FullName 'System.DirectoryServices.Protocols.LdapException' -Namespace 'System.DirectoryServices.Protocols' -ClassName 'LdapException'
            }

            It 'Should classify <TypeName> as <Category>' -ForEach @(
                @{ TypeName = 'System.Net.Sockets.SocketException'; Category = 'Connectivity' }
                @{ TypeName = 'System.DirectoryServices.Protocols.LdapException'; Category = 'LdapConnectivity' }
                @{ TypeName = 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'; Category = 'TargetNotFound' }
                @{ TypeName = 'Microsoft.ActiveDirectory.Management.ADServerDownException'; Category = 'Connectivity' }
            ) {
                $exception = if ('System.Net.Sockets.SocketException' -eq $TypeName)
                {
                    [System.Net.Sockets.SocketException]::new(10060)
                }
                else
                {
                    New-Object -TypeName $TypeName -ArgumentList 'test message'
                }

                $result = Resolve-PSADDsrmFailureDetail -ErrorRecord (script:New-TestErrorRecord -Exception $exception)

                $result.Category | Should -Be $Category
                $result.Remediation | Should -Not -BeNullOrEmpty
            }

            It 'Should classify a directory exception buried in an inner chain' {
                $inner = New-Object -TypeName 'System.DirectoryServices.Protocols.LdapException' -ArgumentList 'bind rejected'
                $outer = [System.FormatException]::new('wrapper', $inner)

                $result = Resolve-PSADDsrmFailureDetail -ErrorRecord (script:New-TestErrorRecord -Exception $outer)

                $result.Category | Should -Be 'LdapConnectivity'
            }
        }

        Context 'Operator feedback' {
            It 'Should narrate the classification and the chain depth' {
                $inner = [System.TimeoutException]::new('timed out')
                $outer = [System.FormatException]::new('wrapper', $inner)

                $verbose = Resolve-PSADDsrmFailureDetail -ErrorRecord (script:New-TestErrorRecord -Exception $outer) -Verbose 4>&1 |
                    Out-String

                $verbose | Should -Match 'Failure classified as Timeout'
                $verbose | Should -Match '2 type'
                $verbose | Should -Match 'System.FormatException'
            }

            It 'Should not echo the flattened exception detail into the narration' {
                <#
                    The detail originates in an exception message this function does not
                    control, so it is returned for deliberate logging rather than pushed onto
                    the verbose stream automatically.
                #>
                $exception = [System.InvalidOperationException]::new('UNEXPECTED-PAYLOAD-MARKER')

                $verbose = Resolve-PSADDsrmFailureDetail -ErrorRecord (script:New-TestErrorRecord -Exception $exception) -Verbose 4>&1 |
                    Select-Object -Skip 0 |
                    Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } |
                    Out-String

                $verbose | Should -Not -Match 'UNEXPECTED-PAYLOAD-MARKER'
            }
        }
    }
}
