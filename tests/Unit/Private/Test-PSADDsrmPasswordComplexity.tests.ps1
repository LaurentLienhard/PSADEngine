BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    BeforeAll {
        <#
            Test material only. Production code never converts a plain string into a
            SecureString; this fixture exists solely to build deterministic test input.
        #>
        function script:New-TestSecureString
        {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
            param ([string]$PlainText)

            return (ConvertTo-SecureString -String $PlainText -AsPlainText -Force)
        }
    }

    Describe 'Test-PSADDsrmPasswordComplexity' {
        Context 'When the password satisfies the default Tier 0 policy' {
            It 'Should accept <Description>' -ForEach @(
                @{ Description = 'upper, lower and digit'; PlainText = 'Abcdefghijk1234' }
                @{ Description = 'upper, lower and symbol'; PlainText = 'Abcdefghijkl-mn' }
                @{ Description = 'all four categories'; PlainText = 'Tr0ub4dor-Horse-Battery!' }
                @{ Description = 'exactly the minimum length'; PlainText = 'Abcdefghijkl12' }
                @{ Description = 'a space treated as a symbol'; PlainText = 'Correct Horse 1' }
            ) {
                $result = script:New-TestSecureString -PlainText $PlainText |
                    Test-PSADDsrmPasswordComplexity

                $result.IsValid | Should -BeTrue
                $result.FailureReason | Should -BeNullOrEmpty
            }

            It 'Should report the correct length and category count' {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Tr0ub4dor-Horse!')

                $result.Length | Should -Be 16
                $result.CategoryCount | Should -Be 4
                $result.HasUpperCase | Should -BeTrue
                $result.HasLowerCase | Should -BeTrue
                $result.HasDigit | Should -BeTrue
                $result.HasNonAlphanumeric | Should -BeTrue
            }
        }

        Context 'When the password violates the policy' {
            It 'Should reject a password shorter than the minimum' {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Abcdefghijk12')

                $result.IsValid | Should -BeFalse
                $result.Length | Should -Be 13
                ($result.FailureReason -join ' ') | Should -Match 'at least 14'
            }

            It 'Should reject a password using too few character categories' {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'abcdefghijklmnopqrst')

                $result.IsValid | Should -BeFalse
                $result.CategoryCount | Should -Be 1
                ($result.FailureReason -join ' ') | Should -Match 'character categories'
            }

            It 'Should accumulate every violation rather than stopping at the first' {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'abcdefg')

                $result.IsValid | Should -BeFalse
                $result.FailureReason.Count | Should -Be 2
            }
        }

        Context 'When the password contains a control character' {
            It 'Should reject <Description> because it would corrupt the ntdsutil input script' -ForEach @(
                @{ Description = 'a carriage return and line feed'; PlainText = "Str0ngEnough!Pass`r`nquit" }
                @{ Description = 'a line feed'; PlainText = "Str0ngEnough!Pass`nquit" }
                @{ Description = 'a tab'; PlainText = "Str0ngEnough!Pass`tvalue" }
                @{ Description = 'a NUL'; PlainText = "Str0ngEnough!Pass`0value" }
            ) {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText $PlainText)

                $result.IsValid | Should -BeFalse
                $result.HasControlChar | Should -BeTrue
                ($result.FailureReason -join ' ') | Should -Match 'control character'
            }
        }

        Context 'When a stricter policy is requested' {
            It 'Should honour a raised minimum length' {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Tr0ub4dor-Horse!') -MinimumLength 24

                $result.IsValid | Should -BeFalse
                ($result.FailureReason -join ' ') | Should -Match 'at least 24'
            }

            It 'Should honour a raised category requirement' {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Abcdefghijk1234') -MinimumCategory 4

                $result.IsValid | Should -BeFalse
                ($result.FailureReason -join ' ') | Should -Match 'at least 4'
            }

            It 'Should reject an out of range minimum length through parameter validation' {
                { Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Abcdefghijk1234') -MinimumLength 0 } |
                    Should -Throw
            }

            It 'Should reject an out of range category requirement through parameter validation' {
                { Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Abcdefghijk1234') -MinimumCategory 5 } |
                    Should -Throw
            }
        }

        Context 'When handling edge cases' {
            It 'Should treat an empty SecureString as a policy failure rather than throwing' {
                $result = Test-PSADDsrmPasswordComplexity -Password ([System.Security.SecureString]::new())

                $result.IsValid | Should -BeFalse
                $result.Length | Should -Be 0
            }

            It 'Should reject a null password through parameter validation' {
                { Test-PSADDsrmPasswordComplexity -Password $null } | Should -Throw
            }

            It 'Should classify non ASCII characters without throwing' {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Passw0rd-Muench3n-Uber')

                $result.IsValid | Should -BeTrue
            }
        }

        Context 'Secret hygiene' {
            It 'Should never place the secret in the returned object' {
                $result = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Tr0ub4dor-Horse!')

                ($result | Out-String) | Should -Not -Match 'Tr0ub4dor'
            }

            It 'Should never place the secret in the verbose stream' {
                $verbose = Test-PSADDsrmPasswordComplexity -Password (script:New-TestSecureString -PlainText 'Tr0ub4dor-Horse!') -Verbose 4>&1 |
                    Out-String

                $verbose | Should -Not -Match 'Tr0ub4dor'
            }
        }
    }
}
