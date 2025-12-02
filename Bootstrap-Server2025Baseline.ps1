# Bootstrap-Server2025Baseline.ps1

param(
    [string]$ConfigUrl = "https://your-repo/Server2025_Baseline.ps1",
    [string]$WorkDir   = "C:\DSC"
)

# --- 1. Ensure DSC modules are installed ------------------------------------

$modules = @(
    "SecurityPolicyDsc",
    "AuditPolicyDsc",
    "GPRegistryPolicyDsc",
    "NetworkingDsc"
)

# Make sure PowerShellGet/PSGallery are usable
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue

function Ensure-Module {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)) {
        Write-Host "Installing module $Name ..."
        Install-Module -Name $Name -Repository PSGallery -Force -Scope AllUsers
    }
    else {
        Write-Host "Module $Name already installed."
    }
}

foreach ($m in $modules) {
    Ensure-Module -Name $m
}

# --- 2. Prepare working folder ----------------------------------------------

New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
Set-Location $WorkDir

# --- 3. Download DSC configuration -----------------------------------------

$ConfigPath = Join-Path $WorkDir "Server2025_Baseline.ps1"

Write-Host "Downloading DSC configuration from $ConfigUrl ..."
Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigPath -UseBasicParsing

# --- 4. Compile DSC configuration ------------------------------------------

. $ConfigPath    # dot-source the configuration

$MofOutput = Join-Path $WorkDir "Compiled"
New-Item -Path $MofOutput -ItemType Directory -Force | Out-Null

Write-Host "Compiling DSC configuration ..."
Server2025_Baseline -NodeName 'localhost' -OutputPath $MofOutput

# --- 5. Configure LCM for drift correction ---------------------------------

[DSCLocalConfigurationManager()]
configuration LCMConfig {
    Node 'localhost' {
        Settings {
            RefreshMode                  = 'Disabled'          # push mode
            ConfigurationMode            = 'ApplyAndAutoCorrect'
            ConfigurationModeFrequencyMins = 30                # how often to re-check
            RebootNodeIfNeeded           = $true
        }
    }
}

$LcmPath = Join-Path $WorkDir "LCM"
New-Item -Path $LcmPath -ItemType Directory -Force | Out-Null

Write-Host "Configuring LCM ..."
LCMConfig -OutputPath $LcmPath
Set-DscLocalConfigurationManager -Path $LcmPath -Verbose

# --- 6. Apply configuration -------------------------------------------------

Write-Host "Applying DSC configuration ..."
Start-DscConfiguration -Path $MofOutput -Force -Verbose -Wait

Write-Host "Baseline applied and LCM set to ApplyAndAutoCorrect."
