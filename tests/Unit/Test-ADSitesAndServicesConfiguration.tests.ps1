BeforeAll {
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../../output/PSADEngine/PSADEngine.psd1'
    if (-not (Test-Path $modulePath)) {
        Write-Warning "Module not found at $modulePath. Building module..."
        & "$PSScriptRoot/../../build.ps1" -Tasks build -Verbose
    }
    Import-Module $modulePath -Force -Verbose
}

Describe 'Test-ADSitesAndServicesConfiguration' {
    Context 'Fonction existe et est exportée' {
        It 'Devrait être disponible en tant que cmdlet' {
            Get-Command Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Devrait avoir les paramètres attendus' {
            $command = Get-Command Test-ADSitesAndServicesConfiguration
            $command.Parameters.Keys | Should -Contain 'Forest'
            $command.Parameters.Keys | Should -Contain 'Server'
            $command.Parameters.Keys | Should -Contain 'Credential'
            $command.Parameters.Keys | Should -Contain 'IncludeDetailedReports'
            $command.Parameters.Keys | Should -Contain 'ExportToCSV'
        }

        It 'Devrait avoir un param Forest en pipeline' {
            $command = Get-Command Test-ADSitesAndServicesConfiguration
            $command.Parameters['Forest'].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } | ForEach-Object {
                $_.ValueFromPipeline | Should -Be $true
            }
        }
    }

    Context 'Signature et comportement' {
        It 'Devrait supporter le CmdletBinding' {
            $command = Get-Command Test-ADSitesAndServicesConfiguration
            $command.CmdletBinding | Should -Be $true
        }

        It 'Devrait avoir une aide détaillée (SYNOPSIS)' {
            $help = Get-Help Test-ADSitesAndServicesConfiguration
            $help.Synopsis | Should -Not -BeNullOrEmpty
            $help.Synopsis | Should -Match 'Audite'
        }

        It 'Devrait documenter les paramètres' {
            $help = Get-Help Test-ADSitesAndServicesConfiguration
            $help.Parameters.Parameter | Where-Object { $_.Name -eq 'Forest' } | ForEach-Object {
                $_.Description.Text | Should -Not -BeNullOrEmpty
            }
        }

        It 'Devrait inclure des exemples' {
            $help = Get-Help Test-ADSitesAndServicesConfiguration
            $help.Examples.Example | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Retour et structure' {
        It 'Devrait retourner un objet PSCustomObject' {
            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result | Should -BeOfType [PSCustomObject]
        }

        It 'Devrait avoir une propriété Summary dans le résultat' {
            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Summary | Should -Not -BeNullOrEmpty
        }

        It 'Devrait avoir une propriété Issues dans le résultat' {
            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Issues | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Détection d''erreurs - Sites orphelins' {
        It 'Devrait détecter un site sans subnet' {
            $mockSite = [PSCustomObject]@{
                Name           = 'TestSite'
                DistinguishedName = 'CN=TestSite,CN=Sites,CN=Configuration,DC=corp,DC=contoso,DC=com'
            }

            $mockSubnet = $null

            Mock -CommandName Get-ADReplicationSite -MockWith { @($mockSite) }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Issues | Where-Object { $_.IssueId -eq 'SITE-001' } | Should -Not -BeNullOrEmpty
        }

        It 'Devrait classer site orphelin en CRITICAL' {
            $mockSite = [PSCustomObject]@{
                Name = 'OrphanSite'
            }

            Mock -CommandName Get-ADReplicationSite -MockWith { @($mockSite) }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $critical = $result.Issues | Where-Object { $_.IssueId -eq 'SITE-001' -and $_.Severity -eq 'CRITICAL' }
            $critical | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Détection d''erreurs - Subnets orphelins' {
        It 'Devrait détecter un subnet sans site assigné' {
            $mockSubnet = [PSCustomObject]@{
                Name = '10.0.1.0/24'
                Site = $null
            }

            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @($mockSubnet) }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Issues | Where-Object { $_.IssueId -eq 'SUBNET-001' } | Should -Not -BeNullOrEmpty
        }

        It 'Devrait classer subnet orphelin en CRITICAL' {
            $mockSubnet = [PSCustomObject]@{
                Name = '192.168.1.0/24'
                Site = ''
            }

            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @($mockSubnet) }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $critical = $result.Issues | Where-Object { $_.IssueId -eq 'SUBNET-001' -and $_.Severity -eq 'CRITICAL' }
            $critical | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Détection d''erreurs - Liaisons inter-site' {
        It 'Devrait détecter une liaison avec moins de 2 sites' {
            $mockSiteLink = [PSCustomObject]@{
                Name          = 'InvalidLink'
                SitesIncluded = @()
                ReplicationFrequencyInMinutes = 15
                Options = 0
            }

            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @($mockSiteLink) }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Issues | Where-Object { $_.IssueId -eq 'SITELINK-004' } | Should -Not -BeNullOrEmpty
        }

        It 'Devrait détecter une fréquence de réplication élevée' {
            $mockSiteLink = [PSCustomObject]@{
                Name          = 'SlowLink'
                SitesIncluded = @('Site1', 'Site2')
                ReplicationFrequencyInMinutes = 240
                Options = 0
            }

            $mockSite1 = [PSCustomObject]@{ Name = 'Site1' }
            $mockSite2 = [PSCustomObject]@{ Name = 'Site2' }

            Mock -CommandName Get-ADReplicationSite -MockWith { @($mockSite1, $mockSite2) }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @($mockSiteLink) }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Issues | Where-Object { $_.IssueId -eq 'SITELINK-002' } | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Résumé et compteurs' {
        It 'Devrait compter correctement les problèmes CRITICAL' {
            $mockSubnet = [PSCustomObject]@{
                Name = '10.0.0.0/8'
                Site = $null
            }

            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @($mockSubnet) }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Summary.CriticalIssues | Should -Be 1
        }

        It 'Devrait inclure le timestamp dans le résumé' {
            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Summary.TimestampUtc | Should -BeOfType [datetime]
        }

        It 'Devrait reporter le nombre de sites analysés' {
            $mockSite1 = [PSCustomObject]@{ Name = 'Site1' }
            $mockSite2 = [PSCustomObject]@{ Name = 'Site2' }

            Mock -CommandName Get-ADReplicationSite -MockWith { @($mockSite1, $mockSite2) }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue
            $result.Summary.SitesAnalyzed | Should -Be 2
        }
    }

    Context 'Paramètres optionnels' {
        It 'Devrait accepter le paramètre Server' {
            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            { Test-ADSitesAndServicesConfiguration -Server 'DC01' -ErrorAction SilentlyContinue } | Should -Not -Throw
        }

        It 'Devrait accepter le paramètre Forest' {
            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            { Test-ADSitesAndServicesConfiguration -Forest 'corp.contoso.com' -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
    }

    Context 'AuditType parameter avec ValidateSet' {
        It 'Devrait avoir le paramètre AuditType' {
            $command = Get-Command Test-ADSitesAndServicesConfiguration
            $command.Parameters.Keys | Should -Contain 'AuditType'
        }

        It 'Devrait valider AuditType avec All, OrphanedSites, OrphanedSubnets, etc' {
            $command = Get-Command Test-ADSitesAndServicesConfiguration
            $auditTypeParam = $command.Parameters['AuditType']
            $auditTypeParam.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object {
                $_.ValidValues | Should -Contain 'All'
                $_.ValidValues | Should -Contain 'OrphanedSites'
                $_.ValidValues | Should -Contain 'OrphanedSubnets'
                $_.ValidValues | Should -Contain 'InvalidSiteLinks'
                $_.ValidValues | Should -Contain 'SlowReplication'
            }
        }

        It 'Devrait exécuter seulement les audits OrphanedSites' {
            $mockSite = [PSCustomObject]@{ Name = 'OrphanSite' }

            Mock -CommandName Get-ADReplicationSite -MockWith { @($mockSite) }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -AuditType OrphanedSites -ErrorAction SilentlyContinue

            # Vérifier que l'audit OrphanedSites a été exécuté
            $result.Issues | Where-Object { $_.IssueId -eq 'SITE-001' } | Should -Not -BeNullOrEmpty
        }

        It 'Devrait exécuter seulement les audits OrphanedSubnets' {
            $mockSubnet = [PSCustomObject]@{
                Name = '10.0.0.0/8'
                Site = $null
            }

            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @($mockSubnet) }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -AuditType OrphanedSubnets -ErrorAction SilentlyContinue

            # Vérifier que l'audit OrphanedSubnets a été exécuté
            $result.Issues | Where-Object { $_.IssueId -eq 'SUBNET-001' } | Should -Not -BeNullOrEmpty
        }

        It 'Devrait exécuter les audits SlowReplication et SmtpLinks' {
            $mockSiteLink = [PSCustomObject]@{
                Name          = 'SlowLink'
                SitesIncluded = @('Site1', 'Site2')
                ReplicationFrequencyInMinutes = 240
                Options = 0
            }

            $mockSite1 = [PSCustomObject]@{ Name = 'Site1' }
            $mockSite2 = [PSCustomObject]@{ Name = 'Site2' }

            Mock -CommandName Get-ADReplicationSite -MockWith { @($mockSite1, $mockSite2) }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @() }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @($mockSiteLink) }

            $result = Test-ADSitesAndServicesConfiguration -AuditType SlowReplication, SmtpLinks -ErrorAction SilentlyContinue

            # Vérifier que l'audit SlowReplication a détecté le problème
            $result.Issues | Where-Object { $_.IssueId -eq 'SITELINK-002' } | Should -Not -BeNullOrEmpty
        }

        It 'Devrait exécuter tous les audits avec All' {
            $mockSite = [PSCustomObject]@{ Name = 'TestSite' }
            $mockSubnet = [PSCustomObject]@{
                Name = '10.0.0.0/8'
                Site = $null
            }

            Mock -CommandName Get-ADReplicationSite -MockWith { @($mockSite) }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @($mockSubnet) }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -AuditType All -ErrorAction SilentlyContinue

            # Vérifier que les audits SITE-001 et SUBNET-001 ont été exécutés
            $result.Issues | Where-Object { $_.IssueId -in @('SITE-001', 'SUBNET-001') } | Should -HaveCount 2
        }

        It 'Devrait défaut à All si AuditType n''est pas spécifié' {
            $mockSubnet = [PSCustomObject]@{
                Name = '10.0.0.0/8'
                Site = $null
            }

            Mock -CommandName Get-ADReplicationSite -MockWith { @() }
            Mock -CommandName Get-ADReplicationSubnet -MockWith { @($mockSubnet) }
            Mock -CommandName Get-ADReplicationSiteLink -MockWith { @() }

            $result = Test-ADSitesAndServicesConfiguration -ErrorAction SilentlyContinue

            # Vérifier que SUBNET-001 a été détecté (audit All par défaut)
            $result.Issues | Where-Object { $_.IssueId -eq 'SUBNET-001' } | Should -Not -BeNullOrEmpty
        }
    }
}
