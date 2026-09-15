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
    }
}
