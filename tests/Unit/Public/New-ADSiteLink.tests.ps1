BeforeAll {
    . $PSScriptRoot\..\..\..\source\Public\New-ADSiteLink.ps1
}

Describe "New-ADSiteLink" {
    BeforeEach {
        Mock Get-Module { return $true }
        Mock Get-ADRootDSE {
            return [PSCustomObject]@{ configurationNamingContext = "CN=Configuration,DC=test,DC=local" }
        }
    }

    Context "When validating Hub and Branch sites" {
        It "Should throw an error if Get-ADRootDSE fails" {
            Mock Get-ADRootDSE { throw "RootDSE Error" }
            { New-ADSiteLink -HubSiteName "Hub1" -TargetBranchSites @("Branch1") } | Should -Throw "Failed to query RootDSE to resolve Configuration Naming Context: RootDSE Error"
        }

        It "Should return early and write error if Hub site does not exist" {
            Mock Get-ADObject { return $false }
            Mock Write-Error {}

            New-ADSiteLink -HubSiteName "MissingHub" -TargetBranchSites @("Branch1")
            
            Should -Invoke -CommandName Write-Error -Times 1 -ParameterFilter { $Message -match "does not exist in the Configuration Partition" }
        }

        It "Should skip Branch site and output status if Branch site does not exist" {
            Mock Get-ADObject {
                param($Identity)
                if ($Identity -match "Hub1") { return $true }
                return $false
            }
            Mock Write-Warning {}

            $Result = New-ADSiteLink -HubSiteName "Hub1" -TargetBranchSites @("MissingBranch")

            Should -Invoke -CommandName Write-Warning -Times 1
            $Result.Status | Should -Be "Skipped"
            $Result.Reason | Should -Be "Branch site object missing"
        }
    }

    Context "When creating or updating Site Links" {
        BeforeEach {
            Mock Get-ADObject { return $true }
        }

        It "Should create a new Site Link if one does not exist" {
            Mock Get-ADReplicationSiteLink { return $null }
            Mock New-ADReplicationSiteLink {
                return [PSCustomObject]@{ DistinguishedName = "CN=Lien Hub1-Branch1,CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=test,DC=local" }
            }
            
            $Result = New-ADSiteLink -HubSiteName "Hub1" -TargetBranchSites @("Branch1")

            Should -Invoke -CommandName New-ADReplicationSiteLink -Times 1 -ParameterFilter { $Name -eq "Lien Hub1-Branch1" }
            $Result.Status | Should -Be "Created"
            $Result.DistinguishedName | Should -Not -BeNullOrEmpty
        }

        It "Should update an existing Site Link if it already exists" {
            Mock Get-ADReplicationSiteLink {
                return [PSCustomObject]@{ DistinguishedName = "CN=Lien Hub1-Branch1,CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=test,DC=local" }
            }
            Mock Set-ADReplicationSiteLink {}
            
            $Result = New-ADSiteLink -HubSiteName "Hub1" -TargetBranchSites @("Branch1")

            Should -Invoke -CommandName Set-ADReplicationSiteLink -Times 1 -ParameterFilter { $Identity -eq "Lien Hub1-Branch1" }
            $Result.Status | Should -Be "Updated"
        }

        It "Should catch exceptions during Site Link creation and output failed status" {
            Mock Get-ADReplicationSiteLink { return $null }
            Mock New-ADReplicationSiteLink { throw "Creation Failed" }
            Mock Write-Error {}

            $Result = New-ADSiteLink -HubSiteName "Hub1" -TargetBranchSites @("Branch1")

            $Result.Status | Should -Be "Failed"
            $Result.Reason | Should -Match "Creation Failed"
            Should -Invoke -CommandName Write-Error -Times 1
        }
    }
}
