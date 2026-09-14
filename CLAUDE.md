# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**PSADEngine** is a PowerShell module for Active Directory management automation, built with the **Sampler framework** and **ModuleBuilder**. It focuses on enterprise-grade Active Directory operations with Tier 0 automation capabilities (e.g., Site Link management).

## Quick Start Commands

### Build the Module
```powershell
./build.ps1 -Tasks build
```
Creates a versioned output directory with the compiled module in `output/`.

### Run Tests
```powershell
./build.ps1 -Tasks test
```
Runs Pester tests with code coverage analysis (85% threshold required).

### Run a Specific Test
```powershell
Invoke-Pester -Path tests/Unit/<TestFile>.tests.ps1 -Verbose
```

### Package for Distribution
```powershell
./build.ps1 -Tasks pack
```
Creates a `.nupkg` file for module distribution.

### Clean Build Artifacts
```powershell
./build.ps1 -Tasks Clean
```
Removes the `output/` directory.

## Project Structure

```
PSADEngine/
├── source/                    # Module source code
│   ├── Classes/              # PowerShell classes (.ps1)
│   │   ├── 1.class1.ps1
│   │   ├── 2.class2.ps1
│   │   └── ...
│   ├── Public/               # Exported cmdlets/functions
│   │   ├── New-ADSiteLink.ps1
│   │   └── Get-Something.ps1
│   ├── Private/              # Internal helper functions
│   │   └── Get-PrivateFunction.ps1
│   ├── en-US/                # Help and localization
│   ├── PSADEngine.psd1       # Module manifest
│   └── PSADEngine.psm1       # Module root file
├── tests/                     # Test suite
│   ├── Unit/                 # Unit tests
│   └── QA/                   # Quality assurance tests
├── build.ps1                 # Build entry point (Invoke-Build wrapper)
├── build.yaml                # ModuleBuilder configuration
├── azure-pipelines.yml       # CI/CD pipeline configuration
├── GitVersion.yml            # Semantic versioning rules
└── output/                   # [Generated] Compiled module artifacts
```

## Build System Architecture

### Build Workflow (build.yaml)
The project uses **InvokeBuild** with **ModuleBuilder tasks**. Key workflows:

- **`.` (default)**: Runs `build` → `test` sequentially
- **`build`**: Clean → Build_Module → Create changelog
- **`test`**: Runs Pester with code coverage threshold validation (85%)
- **`pack`**: Build → Create NuGet package
- **`publish`**: Publish to GitHub + PowerShell Gallery

### ModuleBuilder Configuration
- **BuiltModuleSubdirectory**: `module` — compiled module lives in `output/module/`
- **VersionedOutputDirectory**: `true` — creates version-specific directories (e.g., `output/PSADEngine/0.0.1/`)
- **Encoding**: UTF-8
- **Nested modules**: None currently defined, but available for future use

## Module Organization

### Public Functions
Located in `source/Public/`:
- **New-ADSiteLink** — Creates Active Directory Site Links connecting branch sites to a Hub site (Tier 0 automation)
- **Get-Something** — Sample exported cmdlet
- Export managed in `PSADEngine.psd1` manifest under `FunctionsToExport`

### Private Functions
Located in `source/Private/`:
- Internal helper functions NOT exported to module consumers
- Automatically loaded by PSADEngine.psm1
- Used as dependencies for public functions

### Classes
Located in `source/Classes/`:
- PowerShell classes implementing object models
- Numbered prefix indicates load order (1.class1.ps1 loads before 2.class2.ps1)
- Loaded before functions to ensure type availability

## Code Conventions

### PowerShell Style Guide
- **Naming**: Use PascalCase for cmdlet names (`New-ADSiteLink`) and function names
- **Parameters**: Mandatory parameters first, optional parameters after
- **Help**: Comprehensive comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`)
- **Error Handling**: Use `-ErrorAction Stop` for exceptions; validate prerequisites in `begin` block
- **Validation**: Use `[ValidateNotNullOrEmpty()]` and `[ValidateRange()]` attributes

### Cmdlet Structure Pattern
```powershell
function New-ADSiteLink {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$HubSiteName,
        # ...
    )
    
    begin {
        # Validate prerequisites, initialize
    }
    
    process {
        # Main business logic
        if ($PSCmdlet.ShouldProcess($resource, "Action")) {
            # Implementation
        }
    }
    
    end {
        # Cleanup/finalization
    }
}
```

### Documentation
- **Comment-based Help**: Mandatory for all public functions (helps module users)
- **Typo Intentionality**: Some typos are intentional (e.g., "calss" in Class1.ToString()) — preserve these

## Testing

### Test Framework: Pester
Located in `tests/`:
- **Unit tests**: `tests/Unit/` — Test individual functions and classes in isolation
- **QA tests**: `tests/QA/` — Quality assurance and integration tests
- **Code Coverage Threshold**: 85% (configured in `build.yaml`)

### Running Tests
```powershell
# All tests with coverage reporting
./build.ps1 -Tasks test

# Single test file
Invoke-Pester -Path tests/Unit/SomeTest.tests.ps1 -Verbose

# Specific test by name
Invoke-Pester -Path tests/Unit/SomeTest.tests.ps1 -TestName "specific test name"

# With coverage output
Invoke-Pester -Path tests/ -CodeCoverage source/**/*.ps1 -CodeCoverageOutputFile coverage.xml
```

### Test Organization
Tests follow naming convention: `<ScriptName>.tests.ps1`
- Unit tests verify function behavior in isolation
- QA tests validate integration, error handling, and edge cases

## Dependencies

### Required Modules
- **ActiveDirectory** (RSAT) — Required for cmdlets like `New-ADSiteLink`
- Declared in `RequiredModules` array in `PSADEngine.psd1`

### Build Dependencies
- **Sampler** — Provides InvokeBuild tasks
- **Sampler.GitHubTasks** — GitHub release/publish automation
- **ModuleBuilder** — Compiles and packages the module
- All declared in `RequiredModules.psd1` for development

### CI/CD Pipeline
- **Azure Pipelines** (`azure-pipelines.yml`) — Automated build/test/publish
- **GitVersion** — Semantic versioning based on git history

## Module Manifest (PSADEngine.psd1)

Current state:
- **ModuleVersion**: `0.0.1` (will be overridden by GitVersion in CI/CD)
- **RootModule**: `PSADEngine.psm1`
- **PowerShellVersion**: 5.0+ required
- **Author**: LIENHARD Laurent
- **FunctionsToExport**: Empty (configure to export public cmdlets)
- **CmdletsToExport**: Empty (currently no compiled cmdlets)
- **Description**: "Lot of stuff" (placeholder — update with actual module description)

## Versioning Strategy

**GitVersion** drives semantic versioning:
- Configured in `GitVersion.yml`
- Version is calculated from git history (tags, commits)
- Build script injects computed version into output module manifest
- Avoids manual version bumping in source

## Common Development Tasks

### Add a New Cmdlet
1. Create `source/Public/NewCmdletName.ps1`
2. Implement function following the pattern above
3. Add to `FunctionsToExport` array in `PSADEngine.psd1`
4. Add unit tests in `tests/Unit/NewCmdletName.tests.ps1`
5. Run `./build.ps1 -Tasks test` to verify

### Add a New Class
1. Create `source/Classes/N.ClassName.ps1` (increment N for load order)
2. Implement the class
3. Classes are auto-loaded by PSADEngine.psm1
4. Add tests in `tests/Unit/ClassName.tests.ps1`

### Add a Private Helper Function
1. Create `source/Private/HelperFunctionName.ps1`
2. Implement function (no help required, but comments appreciated)
3. Call from public functions or other private functions
4. Private functions auto-load via PSADEngine.psm1

### Update Module Description
1. Edit `source/PSADEngine.psd1` — update `Description` field
2. No rebuild needed; manifest is copied to output

### Debug Build Issues
```powershell
# Verbose build output
./build.ps1 -Tasks build -Verbose

# Inspect compiled module
Get-ChildItem output/PSADEngine/ -Recurse

# Test module loading
Import-Module output/PSADEngine/0.0.1/PSADEngine.psd1 -Verbose
Get-Command -Module PSADEngine
```

## Git Workflow

### Commit Convention
Follow conventional commits for clarity:
```
feat(siteLinking): add New-ADSiteLink cmdlet
fix(replication): handle missing RootDSE gracefully
docs: update README with examples
test: add unit tests for Site Link validation
```

### Branch Strategy
- Work on feature branches
- Keep `main` deployable
- Test locally before pushing: `./build.ps1 -Tasks test`

## Notes for Future Work

- **Manifest exports**: Update `FunctionsToExport` and `CmdletsToExport` as cmdlets are finalized
- **Module description**: Replace "Lot of stuff" placeholder in manifest and README
- **Localization**: `en-US/` directory prepared for help localization
- **DSC Resources**: Infrastructure exists in build config for DSC resource support (currently commented out)
- **Changelog**: Automatically generated during build from git history; configure `CHANGELOG.md` strategy if needed
