# Test-ADSitesAndServicesConfiguration

## Vue d'ensemble

La fonction `Test-ADSitesAndServicesConfiguration` effectue un audit complet de la configuration des **Sites and Services** dans Active Directory et identifie les erreurs de configuration qui ne respectent pas les best practices Microsoft.

## Objectifs

- ✅ Identifier les sites orphelins (sans subnets assignés)
- ✅ Identifier les subnets orphelins (non assignés à un site)
- ✅ Détecter les subnets dupliqués ou conflictuels
- ✅ Valider les liaisons inter-site (site links)
- ✅ Vérifier la fréquence de réplication
- ✅ Détecter les liaisons SMTP (moins efficaces que RPC)
- ✅ Vérifier la symétrie des liaisons (au moins 2 sites)

## Syntaxe

```powershell
Test-ADSitesAndServicesConfiguration [[-Forest] <string>] [[-Server] <string>] [[-Credential] <PSCredential>] [-IncludeDetailedReports] [-ExportToCSV]
```

## Paramètres

### AuditType
- **Type**: String[] avec ValidateSet
- **Requis**: Non
- **Valeur par défaut**: 'All'
- **Valeurs acceptées**:
  - `All` — Exécute tous les audits (défaut)
  - `OrphanedSites` — Sites sans subnets assignés (SITE-001)
  - `OrphanedSubnets` — Subnets non assignés à un site (SUBNET-001)
  - `DuplicateSubnets` — Subnets en plusieurs exemplaires (SUBNET-002)
  - `InvalidSiteLinks` — Liaisons avec sites inexistants (SITELINK-001)
  - `SlowReplication` — Fréquence de réplication > 180 min (SITELINK-002)
  - `SmtpLinks` — Liaisons utilisant SMTP au lieu de RPC (SITELINK-003)
  - `IncompleteLinks` — Liaisons connectant < 2 sites (SITELINK-004)

- **Description**: Permet de sélectionner les audits à exécuter pour une performance optimale

```powershell
# Vérifier seulement les subnets orphelins
Test-ADSitesAndServicesConfiguration -AuditType OrphanedSubnets

# Vérifier subnets et sites orphelins
Test-ADSitesAndServicesConfiguration -AuditType OrphanedSites, OrphanedSubnets

# Vérifier uniquement les problèmes de réplication
Test-ADSitesAndServicesConfiguration -AuditType SlowReplication, SmtpLinks, InvalidSiteLinks
```

### Forest
- **Type**: String
- **Requis**: Non
- **Valeur par défaut**: Forêt actuelle
- **Description**: La forêt Active Directory à analyser

```powershell
Test-ADSitesAndServicesConfiguration -Forest 'corp.contoso.com'
```

### Server
- **Type**: String
- **Requis**: Non
- **Description**: Le serveur (Domain Controller) à utiliser pour les requêtes

```powershell
Test-ADSitesAndServicesConfiguration -Server 'DC01'
```

### Credential
- **Type**: PSCredential
- **Requis**: Non
- **Description**: Les credentials pour l'accès distant

```powershell
$creds = Get-Credential
Test-ADSitesAndServicesConfiguration -Credential $creds
```

### IncludeDetailedReports
- **Type**: Switch
- **Requis**: Non
- **Description**: Inclut des rapports détaillés pour chaque catégorie d'erreur

```powershell
Test-ADSitesAndServicesConfiguration -IncludeDetailedReports
```

### ExportToCSV
- **Type**: Switch
- **Requis**: Non
- **Description**: Exporte les résultats au format CSV dans le répertoire courant

```powershell
Test-ADSitesAndServicesConfiguration -ExportToCSV
```

## Exemples d'utilisation

### Exemple 1: Audit simple de la forêt locale

```powershell
Test-ADSitesAndServicesConfiguration -Verbose
```

**Sortie attendue**:
```
=== AUDIT SITES AND SERVICES ===
Timestamp: 2026-09-25 10:30:45.123456Z
Sites analysés: 5
Subnets analysés: 12
Liaisons analysées: 4

Résultats:
  ❌ CRITICAL: 2
  ⚠️  WARNING:  3
  ℹ️  INFO:     0
  📊 TOTAL:    5

Détail des problèmes par catégorie:
  - Site Orphelin: 1 problème(s)
  - Réplication Lente: 2 problème(s)
  - Subnet Orphelin: 1 problème(s)
```

### Exemple 2: Audit d'une forêt distante

```powershell
Test-ADSitesAndServicesConfiguration -Forest 'corp.contoso.com' -Server 'dc01.corp.contoso.com'
```

### Exemple 3: Audit avec export CSV

```powershell
Test-ADSitesAndServicesConfiguration -ExportToCSV -Verbose
```

Génère un fichier: `ADSitesAudit_20260925_103045.csv`

### Exemple 4: Audit avec credentials

```powershell
$creds = Get-Credential 'CORP\Administrator'
Test-ADSitesAndServicesConfiguration -Server 'DC01' -Credential $creds
```

### Exemple 5: Audit sélectif - Seulement sites orphelins

```powershell
Test-ADSitesAndServicesConfiguration -AuditType OrphanedSites -Verbose
```

**Avantage**: Plus rapide que l'audit complet (pas de vérification des liaisons)

### Exemple 6: Audit sélectif - Sites et subnets orphelins

```powershell
Test-ADSitesAndServicesConfiguration -AuditType OrphanedSites, OrphanedSubnets -ExportToCSV
```

### Exemple 7: Audit sélectif - Problèmes de réplication uniquement

```powershell
Test-ADSitesAndServicesConfiguration -AuditType SlowReplication, SmtpLinks, InvalidSiteLinks -Verbose
```

**Cas d'usage**: Auditer les performances de réplication inter-site sans vérifier les subnets

## Structure des résultats

La fonction retourne un objet `[PSCustomObject]` avec deux propriétés principales:

### Property: Summary

Contient les compteurs et métadonnées:

```powershell
$result.Summary

TimestampUtc           : 2026-09-25T10:30:45.123456Z
SitesAnalyzed          : 5
SubnetsAnalyzed        : 12
SiteLinksAnalyzed      : 4
TotalIssues            : 5
CriticalIssues         : 2
WarningIssues          : 3
InfoIssues             : 0
```

### Property: Issues

Tableau des problèmes détectés:

```powershell
$result.Issues[0]

IssueId       : SITE-001
Severity      : CRITICAL
Category      : Site Orphelin
Description   : Le site 'BranchSite' n'a pas de subnet assigné
AffectedItem  : BranchSite
Impact        : Les clients de ce site ne peuvent pas être localisés par les services AD
Remediation   : Assigner au moins un subnet au site 'BranchSite' ou supprimer le site si inutilisé
Timestamp     : 2026-09-25T10:30:45.123456Z
```

## Codes d'erreur (IssueId)

| Code | Catégorie | Sévérité | Description |
|------|-----------|----------|-------------|
| SITE-001 | Site Orphelin | CRITICAL | Site sans subnet assigné |
| SUBNET-001 | Subnet Orphelin | CRITICAL | Subnet non assigné à un site |
| SUBNET-002 | Subnet Dupliqué | WARNING | Subnet existant en plusieurs exemplaires |
| SITELINK-001 | Site Link Invalide | CRITICAL | Liaison avec sites inexistants |
| SITELINK-002 | Réplication Lente | WARNING | Fréquence de réplication > 180 min |
| SITELINK-003 | Liaison SMTP | WARNING | Liaison utilisant SMTP au lieu de RPC |
| SITELINK-004 | Liaison Incomplète | CRITICAL | Liaison avec < 2 sites |

## Cas d'usage courants

### Audit avant migration

```powershell
# Exécuter avant une migration AD majeure
$auditResult = Test-ADSitesAndServicesConfiguration -ExportToCSV

# Vérifier les erreurs critiques
$criticalIssues = $auditResult.Issues | Where-Object { $_.Severity -eq 'CRITICAL' }
if ($criticalIssues.Count -gt 0) {
    Write-Error "Erreurs critiques détectées. Migration bloquée."
}
```

### Audit régulier scheduled

```powershell
# Ajouter au scheduler pour audit quotidien
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @"
-NoProfile -Command "Test-ADSitesAndServicesConfiguration -ExportToCSV"
"@

$taskTrigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName 'AD Sites Audit' -Action $taskAction -Trigger $taskTrigger
```

### Audit par site

```powershell
# Auditer uniquement un domaine
Test-ADSitesAndServicesConfiguration -Forest 'subdomain.corp.contoso.com' -Verbose
```

## Performance et considérations

- **Durée estimée**: 30-60 secondes pour une forêt moyenne (10-15 sites)
- **Impact réseau**: Très faible (requêtes AD en lecture seule)
- **Droits requis**: Lecture sur la partition Configuration
- **Tier 0 Impact**: Aucun (audit read-only, sans modification)

## Dépannage

### Erreur: "Impossible de trouver le module Active Directory"

```powershell
# Installer RSAT (Remote Server Administration Tools)
# Windows 10/11: Settings > Apps > Optional Features > RSAT: Active Directory Tools
# Windows Server: Add-WindowsFeature RSAT-AD-PowerShell
```

### Erreur: "Accès refusé"

```powershell
# Utiliser des credentials avec permissions de lecture AD
$creds = Get-Credential 'CORP\account_with_ad_read'
Test-ADSitesAndServicesConfiguration -Credential $creds
```

### Pas d'erreurs détectées mais configuration douteux

```powershell
# Augmenter le verbosité pour plus de détails
Test-ADSitesAndServicesConfiguration -Verbose -InformationAction Continue
```

## Best Practices appliquées

- ✅ Chaque site doit avoir au moins un subnet
- ✅ Chaque subnet doit être assigné à un site
- ✅ Pas de subnets dupliqués (identifiants uniques)
- ✅ Liaisons RPC préférées à SMTP (plus rapide, plus fiable)
- ✅ Fréquence de réplication <= 180 minutes (3 heures)
- ✅ Chaque liaison doit connecter au moins 2 sites

## Lien vers documentation officielle

- [Microsoft: Active Directory Replication Topology](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/active-directory-replication-topology)
- [Microsoft: Sites and Services](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/sites-and-services)
- [Microsoft: Site Link Replication Frequency](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/addssite-link-overview)
