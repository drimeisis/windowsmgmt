# Bootstrap-Server2025Baseline.ps1
param(
    [string]$ConfigUrl = "https://raw.githubusercontent.com/drimeisis/windowsmgmt/refs/heads/main/Server2025_Baseline.ps1",
    [string]$WorkDir   = "C:\DSC"
)

$ErrorActionPreference = 'Stop'

# Ensure TLS 1.2 for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- 1. Ensure NuGet provider and PSGallery trust (no prompts) -------------

# Install NuGet provider silently
$nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
if (-not $nuget) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false -Scope AllUsers
}

# Ensure PSGallery exists and is trusted
$psGallery = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
if (-not $psGallery) {
    Register-PSRepository -Name 'PSGallery' `
        -SourceLocation 'https://www.powershellgallery.com/api/v2' `
        -InstallationPolicy Trusted
} elseif ($psGallery.InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
}

# --- 2. Ensure DSC modules are installed (no prompts) ----------------------

$modules = @(
    "SecurityPolicyDsc",
    "AuditPolicyDsc",
    "GPRegistryPolicyDsc",
    "NetworkingDsc"
)

function Ensure-Module {
    param([string]$Name)

    if (-not (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)) {
        Install-Module -Name $Name -Repository PSGallery -Force -Confirm:$false -Scope AllUsers
    }
}

foreach ($m in $modules) { Ensure-Module -Name $m }

# --- 3. Prepare working folder ---------------------------------------------

New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
Set-Location $WorkDir

# --- 4. Download DSC configuration ----------------------------------------

$ConfigPath = Join-Path $WorkDir "Server2025_Baseline.ps1"
Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigPath -UseBasicParsing

# --- 5. Compile DSC configuration -----------------------------------------

. $ConfigPath

$MofOutput = Join-Path $WorkDir "Compiled"
New-Item -Path $MofOutput -ItemType Directory -Force | Out-Null

Server2025_Baseline -NodeName 'localhost' -OutputPath $MofOutput

# --- 6. Configure LCM for ApplyAndAutoCorrect ------------------------------

[DSCLocalConfigurationManager()]
configuration LCMConfig {
    Node 'localhost' {
        Settings {
            RefreshMode                    = 'Disabled'          # push mode
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            ConfigurationModeFrequencyMins = 30
            RebootNodeIfNeeded             = $true
        }
    }
}

$LcmPath = Join-Path $WorkDir "LCM"
New-Item -Path $LcmPath -ItemType Directory -Force | Out-Null

LCMConfig -OutputPath $LcmPath
Set-DscLocalConfigurationManager -Path $LcmPath -Verbose

# --- 7. Apply DSC configuration -------------------------------------------

Start-DscConfiguration -Path $MofOutput -Force -Verbose -Wait
