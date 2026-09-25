function Test-ADSitesAndServicesConfiguration {
    <#
    .SYNOPSIS
        Audite la configuration Sites and Services dans Active Directory.

    .DESCRIPTION
        Réalise un audit complet ou sélectif de la configuration Sites and Services (AD Sites and Services)
        en vérifiant la conformité aux best practices Microsoft et identifie :
        - Sites orphelins (sans subnets assignés)
        - Subnets orphelins (non assignés à un site)
        - Liaisons inter-site invalides ou mal configurées
        - Subnets dupliqués ou conflictuels
        - Site Links avec fréquence de réplication lente
        - Liaisons SMTP au lieu de RPC

    .PARAMETER Forest
        Forêt Active Directory à analyser. Si non spécifié, utilise la forêt actuelle.

    .PARAMETER Server
        Serveur (Domain Controller) à utiliser pour les requêtes. Si non spécifié, utilise le DC par défaut.

    .PARAMETER Credential
        Credentials pour l'accès distant. Si non spécifié, utilise le contexte actuel.

    .PARAMETER AuditType
        Type d'audit à effectuer. Par défaut, tous les audits sont exécutés.
        Valeurs valides:
        - All: Tous les audits (par défaut)
        - OrphanedSites: Sites sans subnets assignés (SITE-001)
        - OrphanedSubnets: Subnets non assignés à un site (SUBNET-001)
        - DuplicateSubnets: Subnets en plusieurs exemplaires (SUBNET-002)
        - InvalidSiteLinks: Liaisons avec sites inexistants (SITELINK-001)
        - SlowReplication: Fréquence de réplication > 180 min (SITELINK-002)
        - SmtpLinks: Liaisons utilisant SMTP au lieu de RPC (SITELINK-003)
        - IncompleteLinks: Liaisons connectant < 2 sites (SITELINK-004)

    .PARAMETER IncludeDetailedReports
        Inclut des rapports détaillés pour chaque catégorie d'erreur.

    .PARAMETER ExportToCSV
        Exporte les résultats au format CSV.

    .EXAMPLE
        Test-ADSitesAndServicesConfiguration -Forest 'corp.contoso.com' -Verbose

    .EXAMPLE
        Test-ADSitesAndServicesConfiguration -AuditType OrphanedSites, OrphanedSubnets -Server DC01

    .EXAMPLE
        Test-ADSitesAndServicesConfiguration -AuditType SlowReplication -ExportToCSV

    .NOTES
        Requires: Active Directory module (RSAT)
        Minimal Tier 0 Risk: Read-only, no modifications
        Best Practices Reference: Microsoft AD Sites and Services configuration guide
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Forest,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'All',
            'OrphanedSites',
            'OrphanedSubnets',
            'DuplicateSubnets',
            'InvalidSiteLinks',
            'SlowReplication',
            'SmtpLinks',
            'IncompleteLinks'
        )]
        [string[]]$AuditType = 'All',

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetailedReports,

        [Parameter(Mandatory = $false)]
        [switch]$ExportToCSV
    )

    begin {
        Write-Verbose -Message "Initialisation de l'audit Sites and Services."
        $ErrorActionPreference = 'Stop'

        $adParams = @{
            ErrorAction = 'Stop'
        }

        if ($PSBoundParameters.ContainsKey('Server')) {
            $adParams['Server'] = $Server
        }
        if ($PSBoundParameters.ContainsKey('Credential')) {
            $adParams['Credential'] = $Credential
        }

        $issues = [System.Collections.Generic.List[PSCustomObject]]::new()
        $summary = [PSCustomObject]@{
            TotalIssues         = 0
            CriticalIssues      = 0
            WarningIssues       = 0
            InfoIssues          = 0
            SitesAnalyzed       = 0
            SubnetsAnalyzed     = 0
            SiteLinksAnalyzed   = 0
            TimestampUtc        = (Get-Date).ToUniversalTime()
        }
    }

    process {
        try {
            Write-Verbose -Message "Récupération des informations de configuration Sites and Services..."

            # Récupérer la forêt et le contexte
            if (-not $Forest) {
                $Forest = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Name
                Write-Verbose -Message "Forêt détectée: $Forest"
            }

            # Normaliser les types d'audit
            if ($AuditType -contains 'All') {
                $AuditType = @('OrphanedSites', 'OrphanedSubnets', 'DuplicateSubnets', 'InvalidSiteLinks', 'SlowReplication', 'SmtpLinks', 'IncompleteLinks')
            }

            Write-Verbose -Message "Audits sélectionnés: $($AuditType -join ', ')"

            # Récupérer tous les sites
            Write-Verbose -Message "Récupération des sites AD..."
            $adSites = @(Get-ADReplicationSite @adParams -Filter '*' -Properties Description)
            $summary.SitesAnalyzed = $adSites.Count
            Write-Verbose -Message "Nombre de sites trouvés: $($adSites.Count)"

            # Récupérer tous les subnets
            Write-Verbose -Message "Récupération des subnets AD..."
            $adSubnets = @(Get-ADReplicationSubnet @adParams -Filter '*' -Properties Description)
            $summary.SubnetsAnalyzed = $adSubnets.Count
            Write-Verbose -Message "Nombre de subnets trouvés: $($adSubnets.Count)"

            # Récupérer tous les site links (seulement si nécessaire)
            if ($AuditType -match 'InvalidSiteLinks|SlowReplication|SmtpLinks|IncompleteLinks') {
                Write-Verbose -Message "Récupération des liaisons inter-site..."
                $adSiteLinks = @(Get-ADReplicationSiteLink @adParams -Filter '*' -Properties ReplicationFrequencyInMinutes, Options)
                $summary.SiteLinksAnalyzed = $adSiteLinks.Count
                Write-Verbose -Message "Nombre de liaisons trouvées: $($adSiteLinks.Count)"
            }

            # Audit: Sites orphelins
            if ($AuditType -contains 'OrphanedSites') {
                Write-Verbose -Message "Audit OrphanedSites: Identification des sites orphelins..."
                $sitesWithSubnets = @($adSubnets | Select-Object -ExpandProperty Site -Unique)
                foreach ($site in $adSites) {
                    if ($site.Name -notin $sitesWithSubnets) {
                        $issue = [PSCustomObject]@{
                            IssueId       = 'SITE-001'
                            Severity      = 'CRITICAL'
                            Category      = 'Site Orphelin'
                            Description   = "Le site '$($site.Name)' n'a pas de subnet assigné"
                            AffectedItem  = $site.Name
                            Impact        = 'Les clients de ce site ne peuvent pas être localisés par les services AD'
                            Remediation   = "Assigner au moins un subnet au site '$($site.Name)' ou supprimer le site si inutilisé"
                            Timestamp     = (Get-Date).ToUniversalTime()
                        }
                        $issues.Add($issue)
                        Write-Warning -Message "CRITICAL: Site orphelin détecté: $($site.Name)"
                    }
                }
            }

            # Audit: Subnets orphelins
            if ($AuditType -contains 'OrphanedSubnets') {
                Write-Verbose -Message "Audit OrphanedSubnets: Identification des subnets orphelins..."
                foreach ($subnet in $adSubnets) {
                    if ([string]::IsNullOrEmpty($subnet.Site)) {
                        $issue = [PSCustomObject]@{
                            IssueId       = 'SUBNET-001'
                            Severity      = 'CRITICAL'
                            Category      = 'Subnet Orphelin'
                            Description   = "Le subnet '$($subnet.Name)' n'est assigné à aucun site"
                            AffectedItem  = $subnet.Name
                            Impact        = 'Ce subnet ne sera pas utilisé pour la localisation de sites'
                            Remediation   = "Assigner le subnet '$($subnet.Name)' à un site ou le supprimer"
                            Timestamp     = (Get-Date).ToUniversalTime()
                        }
                        $issues.Add($issue)
                        Write-Warning -Message "CRITICAL: Subnet orphelin détecté: $($subnet.Name)"
                    }
                }
            }

            # Audit: Subnets dupliqués
            if ($AuditType -contains 'DuplicateSubnets') {
                Write-Verbose -Message "Audit DuplicateSubnets: Vérification des subnets dupliqués..."
                $subnetNames = $adSubnets | Group-Object -Property Name
                foreach ($group in $subnetNames | Where-Object { $_.Count -gt 1 }) {
                    $issue = [PSCustomObject]@{
                        IssueId       = 'SUBNET-002'
                        Severity      = 'WARNING'
                        Category      = 'Subnet Dupliqué'
                        Description   = "Le subnet '$($group.Name)' existe en plusieurs exemplaires ($($group.Count) fois)"
                        AffectedItem  = $group.Name
                        Impact        = 'Comportement imprévisible lors de la localisation de sites'
                        Remediation   = "Fusionner ou supprimer les doublons pour le subnet '$($group.Name)'"
                        Timestamp     = (Get-Date).ToUniversalTime()
                    }
                    $issues.Add($issue)
                    Write-Warning -Message "WARNING: Subnet dupliqué détecté: $($group.Name)"
                }
            }

            # Audit: Site Links invalides
            if ($AuditType -contains 'InvalidSiteLinks') {
                Write-Verbose -Message "Audit InvalidSiteLinks: Vérification des liaisons inter-site..."
                $validSiteNames = @($adSites | Select-Object -ExpandProperty Name)
                foreach ($siteLink in $adSiteLinks) {
                    $invalidSites = @($siteLink.SitesIncluded | Where-Object { $_ -notin $validSiteNames })
                    if ($invalidSites.Count -gt 0) {
                        $issue = [PSCustomObject]@{
                            IssueId       = 'SITELINK-001'
                            Severity      = 'CRITICAL'
                            Category      = 'Site Link Invalide'
                            Description   = "La liaison '$($siteLink.Name)' référence des sites inexistants: $($invalidSites -join ', ')"
                            AffectedItem  = $siteLink.Name
                            Impact        = 'La réplication inter-site ne fonctionnera pas correctement'
                            Remediation   = "Corriger ou supprimer la liaison '$($siteLink.Name)'"
                            Timestamp     = (Get-Date).ToUniversalTime()
                        }
                        $issues.Add($issue)
                        Write-Warning -Message "CRITICAL: Site Link invalide détecté: $($siteLink.Name)"
                    }
                }
            }

            # Audit: Réplication lente
            if ($AuditType -contains 'SlowReplication') {
                Write-Verbose -Message "Audit SlowReplication: Vérification de la fréquence de réplication..."
                foreach ($siteLink in $adSiteLinks) {
                    if ($siteLink.ReplicationFrequencyInMinutes -gt 180) {
                        $issue = [PSCustomObject]@{
                            IssueId       = 'SITELINK-002'
                            Severity      = 'WARNING'
                            Category      = 'Réplication Lente'
                            Description   = "La liaison '$($siteLink.Name)' a une fréquence de réplication élevée: $($siteLink.ReplicationFrequencyInMinutes) minutes"
                            AffectedItem  = $siteLink.Name
                            Impact        = 'La propagation des changements AD sera lente (>3h entre les DCs)'
                            Remediation   = "Réduire la fréquence de réplication pour la liaison '$($siteLink.Name)' (recommandé: 15-60 min)"
                            Timestamp     = (Get-Date).ToUniversalTime()
                        }
                        $issues.Add($issue)
                        Write-Warning -Message "WARNING: Réplication lente détectée sur liaison: $($siteLink.Name)"
                    }
                }
            }

            # Audit: Liaisons SMTP
            if ($AuditType -contains 'SmtpLinks') {
                Write-Verbose -Message "Audit SmtpLinks: Vérification du protocole de liaison..."
                foreach ($siteLink in $adSiteLinks) {
                    $isSmtpOnly = ($siteLink.Options -band 0x00000004) -eq 0x00000004
                    if ($isSmtpOnly) {
                        $issue = [PSCustomObject]@{
                            IssueId       = 'SITELINK-003'
                            Severity      = 'WARNING'
                            Category      = 'Liaison SMTP'
                            Description   = "La liaison '$($siteLink.Name)' utilise SMTP au lieu de RPC"
                            AffectedItem  = $siteLink.Name
                            Impact        = 'Réplication moins fiable et moins efficace qu''avec RPC'
                            Remediation   = "Remplacer par une liaison RPC si possible pour '$($siteLink.Name)'"
                            Timestamp     = (Get-Date).ToUniversalTime()
                        }
                        $issues.Add($issue)
                        Write-Warning -Message "WARNING: Liaison SMTP détectée sur: $($siteLink.Name)"
                    }
                }
            }

            # Audit: Liaisons incomplètes
            if ($AuditType -contains 'IncompleteLinks') {
                Write-Verbose -Message "Audit IncompleteLinks: Vérification de la complétude des liaisons..."
                foreach ($siteLink in $adSiteLinks) {
                    if ($siteLink.SitesIncluded.Count -lt 2) {
                        $issue = [PSCustomObject]@{
                            IssueId       = 'SITELINK-004'
                            Severity      = 'CRITICAL'
                            Category      = 'Liaison Incomplète'
                            Description   = "La liaison '$($siteLink.Name)' connecte moins de 2 sites ($($siteLink.SitesIncluded.Count))"
                            AffectedItem  = $siteLink.Name
                            Impact        = 'La liaison ne relie aucun site (non fonctionnelle)'
                            Remediation   = "Ajouter au moins 2 sites à la liaison '$($siteLink.Name)' ou la supprimer"
                            Timestamp     = (Get-Date).ToUniversalTime()
                        }
                        $issues.Add($issue)
                        Write-Warning -Message "CRITICAL: Liaison incomplète détectée: $($siteLink.Name)"
                    }
                }
            }

            # Mise à jour du résumé
            $summary.TotalIssues = $issues.Count
            $summary.CriticalIssues = @($issues | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
            $summary.WarningIssues = @($issues | Where-Object { $_.Severity -eq 'WARNING' }).Count
            $summary.InfoIssues = @($issues | Where-Object { $_.Severity -eq 'INFO' }).Count

            Write-Verbose -Message "Audit terminé. Résumé: $($summary.CriticalIssues) Critical, $($summary.WarningIssues) Warning, $($summary.InfoIssues) Info"
        }
        catch [Microsoft.ActiveDirectory.Management.ADException] {
            Write-Error -Message "Erreur AD lors de la requête: $($_.Exception.Message)" -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Error -Message "Erreur inattendue: $($_.Exception.Message)" -ErrorAction Stop
        }
    }

    end {
        # Retourner les résultats
        $result = [PSCustomObject]@{
            Summary = $summary
            Issues  = @($issues)
        }

        # Afficher le résumé dans la console
        Write-Host "`n=== AUDIT SITES AND SERVICES ===" -ForegroundColor Cyan
        Write-Host "Timestamp: $($summary.TimestampUtc)" -ForegroundColor Gray
        Write-Host "Sites analysés: $($summary.SitesAnalyzed)" -ForegroundColor Gray
        Write-Host "Subnets analysés: $($summary.SubnetsAnalyzed)" -ForegroundColor Gray
        Write-Host "Liaisons analysées: $($summary.SiteLinksAnalyzed)" -ForegroundColor Gray
        Write-Host "`nRésultats:" -ForegroundColor Cyan
        Write-Host "  ❌ CRITICAL: $($summary.CriticalIssues)" -ForegroundColor Red
        Write-Host "  ⚠️  WARNING:  $($summary.WarningIssues)" -ForegroundColor Yellow
        Write-Host "  ℹ️  INFO:     $($summary.InfoIssues)" -ForegroundColor Blue
        Write-Host "  📊 TOTAL:    $($summary.TotalIssues)" -ForegroundColor Magenta
        Write-Host "`n" -ForegroundColor Cyan

        # Grouper et afficher les problèmes par catégorie
        if ($issues.Count -gt 0) {
            Write-Host "Détail des problèmes par catégorie:" -ForegroundColor Cyan
            $issues | Group-Object -Property Category | ForEach-Object {
                Write-Host "  - $($_.Name): $($_.Count) problème(s)" -ForegroundColor Yellow
            }
            Write-Host "`n" -ForegroundColor Cyan
        }

        # Export CSV si demandé
        if ($ExportToCSV) {
            $csvPath = "ADSitesAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $issues | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "Résultats exportés vers: $csvPath" -ForegroundColor Green
        }

        return $result
    }
}
