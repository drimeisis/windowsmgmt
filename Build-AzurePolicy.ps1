# Build-Sandboxed.ps1
# Creates a clean, isolated environment to compile and package the DSC configuration
# bypassing any version conflicts on the host machine.

param(
    [string]$ResourceGroupName    = "demo-rg-arc-gcp",
    [string]$StorageAccountName   = "testacc001010", 
    [string]$StorageContainerName = "dsc-configs",
    [string]$ConfigFilePath       = "C:\DSC\Server2025_Baseline.ps1",
    [string]$WorkDir              = "C:\DSC\SandboxBuild",
    [string]$PolicyName           = "Audit-Server2025-Baseline"
)

$ErrorActionPreference = 'Stop'

# --- 1. setup Sandbox Directory --------------------------------------------
Write-Host "Step 1: Preparing Sandbox at $WorkDir..."
if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
$ModuleDir = Join-Path $WorkDir "Modules"
New-Item $ModuleDir -ItemType Directory -Force | Out-Null

# --- 2. Download Fresh Modules to Sandbox ----------------------------------
Write-Host "Step 2: Saving clean modules locally..."
$RequiredModules = @(
    "SecurityPolicyDsc", 
    "AuditPolicyDsc", 
    "GPRegistryPolicyDsc", 
    "NetworkingDsc", 
    "GuestConfiguration"
)

foreach ($mod in $RequiredModules) {
    Write-Host "   - Downloading $mod..."
    # We save to our temp folder so we control exactly which version exists
    Save-Module -Name $mod -Path $ModuleDir -Force
}

# --- 3. Isolate Environment ------------------------------------------------
Write-Host "Step 3: Isolating PowerShell Session..."

# Save original path to restore later if needed
$OriginalModulePath = $env:PSModulePath

# Set path to ONLY our sandbox + System32 (essential for basic PS commands)
# We deliberately EXCLUDE 'C:\Program Files\WindowsPowerShell\Modules'
$env:PSModulePath = "$ModuleDir;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"

Write-Host "   - Module Path restricted. Loaded modules:"
Get-Module -ListAvailable | Select-Object Name, Version | Format-Table -AutoSize

# --- 4. Authenticate (Device Code) -----------------------------------------
Write-Host "Step 4: Connecting to Azure..."
# We try-catch because changing the module path might affect Az module loading
# so we load Az explicitly from the system if needed, or assume it's loaded in parent.
try {
    # If Az is already loaded in memory, this works. 
    # If not, we might need to add its path back or just rely on parent session.
    $null = Get-AzContext -ErrorAction Stop
    Write-Host "   - Already connected."
}
catch {
    Write-Warning "   - Please check your browser for Device Code login."
    # We temporarily add Program Files back just to load Az if it's missing
    $env:PSModulePath = $OriginalModulePath
    Connect-AzAccount -UseDeviceAuthentication
    # Re-isolate
    $env:PSModulePath = "$ModuleDir;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
}

# --- 5. Compile MOF --------------------------------------------------------
Write-Host "Step 5: Compiling MOF in isolation..."
$MofDir = Join-Path $WorkDir "MOF"
New-Item $MofDir -ItemType Directory -Force | Out-Null

# Load the config
. $ConfigFilePath

# Compile
Server2025_Baseline -NodeName 'localhost' -OutputPath $MofDir

# Rename for Guest Config requirement
$OldMof = Join-Path $MofDir "localhost.mof"
$NewMof = Join-Path $MofDir "Server2025_Baseline.mof"
Rename-Item -Path $OldMof -NewName "Server2025_Baseline.mof" -Force

# --- 6. Package (.zip) -----------------------------------------------------
Write-Host "Step 6: Packaging (This should now succeed)..."
$PackageDir = Join-Path $WorkDir "Package"
New-Item $PackageDir -ItemType Directory -Force | Out-Null

# Import GuestConfiguration from our CLEAN folder
Import-Module GuestConfiguration -Force

New-GuestConfigurationPackage `
    -Name "Server2025_Baseline" `
    -Configuration $NewMof `
    -Path $PackageDir `
    -Force

# --- 7. Upload & Publish ---------------------------------------------------
Write-Host "Step 7: Uploading and Publishing..."

# Restore path temporarily to ensure Az modules work fine for upload
$env:PSModulePath = $OriginalModulePath

$Context = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context

# Ensure Container
if (-not (Get-AzStorageContainer -Name $StorageContainerName -Context $Context -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $StorageContainerName -Context $Context -Permission Blob
}

# Upload Zip
$ZipPath = Join-Path $PackageDir "Server2025_Baseline.zip"
Set-AzStorageBlobContent -File $ZipPath -Container $StorageContainerName -Blob "Server2025_Baseline.zip" -Context $Context -Force

# SAS Token
$SasToken = New-AzStorageBlobSASToken -Container $StorageContainerName -Blob "Server2025_Baseline.zip" -Permission r -Context $Context -StartTime (Get-Date) -ExpiryTime (Get-Date).AddYears(3) -FullUri

# Policy
$PolicyDir = Join-Path $WorkDir "Policy"
New-Item $PolicyDir -ItemType Directory -Force | Out-Null

New-GuestConfigurationPolicy `
    -ContentUri $SasToken `
    -DisplayName $PolicyName `
    -Description "Enforces Server 2025 Baseline via Guest Configuration" `
    -Path $PolicyDir `
    -Platform Windows `
    -Mode ApplyAndAutoCorrect `
    -Verbose

$PolicyJson = Get-ChildItem "$PolicyDir\*.json" | Select-Object -First 1
Publish-GuestConfigurationPolicy -Path $PolicyJson.FullName -Verbose

Write-Host "SUCCESS. Policy '$PolicyName' has been published."
