BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    Describe 'Get-PSADDomainHintFromIdentity' {
        Context 'When the identity is a distinguished name' {
            It 'Should derive <Expected>' -ForEach @(
                @{
                    Identity   = 'CN=DC01,OU=Domain Controllers,DC=corp,DC=contoso,DC=com'
                    ServerName = 'DC01'
                    Expected   = 'corp.contoso.com'
                }
                @{
                    Identity   = 'CN=DC01,OU=Domain Controllers,DC=fabrikam,DC=local'
                    ServerName = 'DC01'
                    Expected   = 'fabrikam.local'
                }
                @{
                    Identity   = 'CN=NTDS Settings,CN=DC03,CN=Servers,CN=Branch,CN=Sites,CN=Configuration,DC=child,DC=corp,DC=contoso,DC=com'
                    ServerName = 'DC03'
                    Expected   = 'child.corp.contoso.com'
                }
            ) {
                Get-PSADDomainHintFromIdentity -Identity $Identity -ServerName $ServerName | Should -Be $Expected
            }

            It 'Should prefer the distinguished name over the server name' {
                $result = Get-PSADDomainHintFromIdentity -Identity 'CN=DC01,DC=child,DC=corp,DC=contoso,DC=com' -ServerName 'DC01.corp.contoso.com'

                $result | Should -Be 'child.corp.contoso.com'
            }
        }

        Context 'When the identity is a fully qualified server name' {
            It 'Should strip the host label from <ServerName>' -ForEach @(
                @{ Identity = 'DC01.corp.contoso.com'; ServerName = 'DC01.corp.contoso.com'; Expected = 'corp.contoso.com' }
                @{ Identity = 'DC02.fabrikam.local'; ServerName = 'DC02.fabrikam.local'; Expected = 'fabrikam.local' }
            ) {
                Get-PSADDomainHintFromIdentity -Identity $Identity -ServerName $ServerName | Should -Be $Expected
            }
        }

        Context 'When no domain can be derived' {
            It 'Should return an empty string for a bare NetBIOS name' {
                Get-PSADDomainHintFromIdentity -Identity 'DC01' -ServerName 'DC01' | Should -Be ([System.String]::Empty)
            }
        }

        Context 'Parameter validation' {
            It 'Should reject an empty identity' {
                { Get-PSADDomainHintFromIdentity -Identity '' -ServerName 'DC01' } | Should -Throw
            }

            It 'Should reject an empty server name' {
                { Get-PSADDomainHintFromIdentity -Identity 'DC01' -ServerName '' } | Should -Throw
            }
        }
    }
}
