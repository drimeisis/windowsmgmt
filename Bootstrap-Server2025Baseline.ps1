# Bootstrap-Server2025Baseline.ps1
# Unattended DSC Bootstrap for Azure Arc / Windows Server 2025

param(
    [string]$ConfigUrl = "https://raw.githubusercontent.com/drimeisis/windowsmgmt/refs/heads/main/Server2025_Baseline.ps1",
    [string]$WorkDir   = "C:\DSC"
)

# Stop on any error to prevent cascading failures
$ErrorActionPreference = 'Stop'

# --- 1. System Prep & Module Installation ------------------------------------

Write-Host "Initializing environment..."

# Enforce TLS 1.2 (Required for PowerShell Gallery)
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
    # Download content
    $Response = Invoke-WebRequest -Uri $ConfigUrl -UseBasicParsing
    
    # Validation: Ensure we didn't download an HTML error page
    if ($Response.Content -like "<!DOCTYPE html>*") {
        Throw "The downloaded file appears to be an HTML webpage, not a raw PS1 file. Check the URL."
    }

    # Save to disk with explicit UTF8 encoding
    $Response.Content | Set-Content -Path $ConfigPath -Encoding UTF8 -Force
    
    # CRITICAL: Unblock the file to prevent 'Mark of the Web' security errors
    Unblock-File -Path $ConfigPath
}
catch {
    Write-Error "CRITICAL DOWNLOAD ERROR: $($_.Exception.Message)"
    exit 1
}

# --- 4. Compile DSC configuration ------------------------------------------

Write-Host "Loading configuration into memory..."
try {
    # Dot-source the configuration file
    . $ConfigPath
}
catch {
    Write-Error "COMPILATION ERROR: The configuration file contains syntax errors."
    Write-Error $_.Exception.Message
    exit 1
}

$MofOutput = Join-Path $WorkDir "Compiled"
if (-not (Test-Path $MofOutput)) {
    New-Item -Path $MofOutput -ItemType Directory -Force | Out-Null
}

Write-Host "Compiling DSC configuration ..."
try {
    # Generate the MOF file
    Server2025_Baseline -NodeName 'localhost' -OutputPath $MofOutput
}
catch {
    Write-Error "MOF GENERATION ERROR: $($_.Exception.Message)"
    Write-Error "Tip: Verify property names in the GitHub script match the DSC resource definition."
    exit 1
}

# --- 5. Configure LCM for drift correction ---------------------------------

[DSCLocalConfigurationManager()]
configuration LCMConfig {
    Node 'localhost' {
        Settings {
            # 'Push' allows the local scheduler to run ApplyAndAutoCorrect
            RefreshMode                    = 'Push'
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            ConfigurationModeFrequencyMins = 30
            # Note: If a reboot triggers, Azure Arc may report 'Failed' as the script exits early.
            RebootNodeIfNeeded             = $true
        }
    }
}

$LcmPath = Join-Path $WorkDir "LCM"
if (-not (Test-Path $LcmPath)) {
    New-Item -Path $LcmPath -ItemType Directory -Force | Out-Null
}

Write-Host "Configuring LCM ..."
try {
    LCMConfig -OutputPath $LcmPath
    Set-DscLocalConfigurationManager -Path $LcmPath -Verbose
}
catch {
    Write-Error "LCM CONFIGURATION ERROR: $($_.Exception.Message)"
    exit 1
}

# --- 6. Apply configuration -------------------------------------------------

Write-Host "Applying DSC configuration..."
try {
    # Start-DscConfiguration will throw if it fails; -Wait ensures we see the result
    Start-DscConfiguration -Path $MofOutput -Force -Verbose -Wait
}
catch {
    # If a reboot is pending, this catch block might not execute, which is normal for DSC
    Write-Error "CONFIGURATION APPLICATION ERROR: $($_.Exception.Message)"
    exit 1
}

Write-Host "Baseline successfully applied. LCM is monitoring for drift."
