BeforeDiscovery {
    $script:dscModuleName = 'PSADEngine'

    Import-Module -Name $script:dscModuleName -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    Describe 'ConvertTo-PSADDomainControllerName' {
        Context 'When a distinguished name is supplied' {
            It 'Should return <Expected> for <Identity>' -ForEach @(
                @{
                    Identity = 'CN=DC01,OU=Domain Controllers,DC=corp,DC=contoso,DC=com'
                    Expected = 'DC01'
                }
                @{
                    Identity = 'CN=DC-02,OU=Domain Controllers,DC=fabrikam,DC=local'
                    Expected = 'DC-02'
                }
                @{
                    Identity = 'CN=NTDS Settings,CN=DC03,CN=Servers,CN=Branch-Site,CN=Sites,CN=Configuration,DC=corp,DC=contoso,DC=com'
                    Expected = 'DC03'
                }
            ) {
                ConvertTo-PSADDomainControllerName -Identity $Identity | Should -Be $Expected
            }

            It 'Should un-escape a comma escaped inside the relative distinguished name' {
                ConvertTo-PSADDomainControllerName -Identity 'CN=DC01,OU=Domain Controllers,DC=corp,DC=contoso,DC=com' |
                    Should -Be 'DC01'
            }
        }

        Context 'When a short or qualified name is supplied' {
            It 'Should return <Expected> for <Identity>' -ForEach @(
                @{ Identity = 'DC01'; Expected = 'DC01' }
                @{ Identity = 'DC01.corp.contoso.com'; Expected = 'DC01.corp.contoso.com' }
                @{ Identity = 'DC01$'; Expected = 'DC01' }
                @{ Identity = '  DC01  '; Expected = 'DC01' }
                @{ Identity = 'dc-01.fabrikam.local'; Expected = 'dc-01.fabrikam.local' }
            ) {
                ConvertTo-PSADDomainControllerName -Identity $Identity | Should -Be $Expected
            }
        }

        Context 'When the identity would be unsafe to embed in an ntdsutil directive' {
            It 'Should reject <Identity> because it could inject an ntdsutil command' -ForEach @(
                @{ Identity = "DC01`r`nquit" }
                @{ Identity = 'DC01 quit' }
                @{ Identity = 'DC01;shutdown' }
                @{ Identity = 'DC01|calc' }
                @{ Identity = 'DC01&whoami' }
                @{ Identity = 'CN=DC01 quit,DC=corp,DC=contoso,DC=com' }
                @{ Identity = 'DC01"' }
            ) {
                { ConvertTo-PSADDomainControllerName -Identity $Identity } |
                    Should -Throw -ExpectedMessage '*not permitted in a host name*'
            }

            It 'Should reject a name longer than the maximum host name length' {
                $tooLong = 'D' * 300

                { ConvertTo-PSADDomainControllerName -Identity $tooLong } |
                    Should -Throw -ExpectedMessage '*exceeds 255 characters*'
            }

            It 'Should reject whitespace only input' {
                { ConvertTo-PSADDomainControllerName -Identity '   ' } |
                    Should -Throw -ExpectedMessage '*blank or whitespace*'
            }

            It 'Should reject a null or empty identity through parameter validation' {
                { ConvertTo-PSADDomainControllerName -Identity '' } | Should -Throw
            }
        }

        Context 'When values arrive over the pipeline' {
            It 'Should process every element' {
                $result = @('DC01', 'CN=DC02,DC=corp,DC=contoso,DC=com', 'DC03$' | ConvertTo-PSADDomainControllerName)

                $result | Should -Be @('DC01', 'DC02', 'DC03')
            }
        }
    }
}
