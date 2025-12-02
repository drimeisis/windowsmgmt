# Bootstrap-Server2025Baseline.ps1
# Designed for Unattended Execution via Azure Arc

param(
    [string]$ConfigUrl = "https://raw.githubusercontent.com/drimeisis/windowsmgmt/refs/heads/main/Server2025_Baseline.ps1",
    [string]$WorkDir   = "C:\DSC"
)

# Standardize error preference to stop on failures
$ErrorActionPreference = 'Stop'

# --- 1. System Prep & Module Installation ------------------------------------

Write-Host "Initializing environment..."

# Enforce TLS 1.2 for PowerShell Gallery connectivity
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Check/Install NuGet Provider with ForceBootstrap (Critical for unattended runs)
if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
    Write-Host "Bootstrapping NuGet Provider..."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap
}

# Trust PSGallery to suppress "Are you sure?" prompts
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue

$modules = @(
    "SecurityPolicyDsc",
    "AuditPolicyDsc",
    "GPRegistryPolicyDsc",
    "NetworkingDsc"
)

function Ensure-Module {
    param([string]$Name)

    if (-not (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)) {
        Write-Host "Installing module $Name ..."
        # -AllowClobber ensures installation even if command names conflict
        Install-Module -Name $Name -Repository PSGallery -Force -Scope AllUsers -AllowClobber
    }
    else {
        Write-Host "Module $Name is already installed."
    }
}

foreach ($m in $modules) {
    Ensure-Module -Name $m
}

# --- 2. Prepare working folder ----------------------------------------------

if (-not (Test-Path $WorkDir)) {
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
}
Set-Location $WorkDir

# --- 3. Download DSC configuration -----------------------------------------

$ConfigPath = Join-Path $WorkDir "Server2025_Baseline.ps1"

Write-Host "Downloading DSC configuration from $ConfigUrl ..."
try {
    # Download content as string first, then save as UTF8 to ensure no BOM/Encoding issues
    $Content = (Invoke-WebRequest -Uri $ConfigUrl -UseBasicParsing).Content
    $Content | Set-Content -Path $ConfigPath -Encoding UTF8 -Force
}
catch {
    Write-Error "Failed to download configuration file. Verify URL and Internet access."
    # Print specific error to logs for debugging
    Write-Host $_.Exception.Message
    exit 1
}

# --- 4. Compile DSC configuration ------------------------------------------

try {
    . $ConfigPath # dot-source the configuration
}
catch {
    Write-Error "Failed to load the downloaded configuration file. The script may be corrupt."
    exit 1
}

$MofOutput = Join-Path $WorkDir "Compiled"
if (-not (Test-Path $MofOutput)) {
    New-Item -Path $MofOutput -ItemType Directory -Force | Out-Null
}

Write-Host "Compiling DSC configuration ..."
# Assuming the configuration name inside the file is 'Server2025_Baseline'
Server2025_Baseline -NodeName 'localhost' -OutputPath $MofOutput

# --- 5. Configure LCM for drift correction ---------------------------------

[DSCLocalConfigurationManager()]
configuration LCMConfig {
    Node 'localhost' {
        Settings {
            # UPDATED: Must be 'Push' to allow AutoCorrect to run on a schedule. 
            # 'Disabled' would turn off the consistency check entirely.
            RefreshMode                    = 'Push'
            
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            ConfigurationModeFrequencyMins = 30
            
            # NOTE: If a reboot triggers, Azure Arc may report a status of 'Failed/Cancelled' 
            # because the script stops communicating. This is expected behavior for DSC.
            RebootNodeIfNeeded             = $true
        }
    }
}

$LcmPath = Join-Path $WorkDir "LCM"
if (-not (Test-Path $LcmPath)) {
    New-Item -Path $LcmPath -ItemType Directory -Force | Out-Null
}

Write-Host "Configuring LCM ..."
LCMConfig -OutputPath $LcmPath
Set-DscLocalConfigurationManager -Path $LcmPath -Verbose

# --- 6. Apply configuration -------------------------------------------------

Write-Host "Applying DSC configuration..."
# Wait ensures the script doesn't finish until DSC is done (unless reboot happens first)
Start-DscConfiguration -Path $MofOutput -Force -Verbose -Wait

Write-Host "Baseline successfully applied. LCM is monitoring for drift."
