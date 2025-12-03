# Build-AzurePolicy.ps1


param(
    [string]$ResourceGroupName    = "demo-rg-arc-gcp",
    [string]$StorageAccountName   = "testacc001010", 
    [string]$StorageContainerName = "dsc-configs",

    # We use Absolute Paths now to avoid "File Not Found" errors
    [string]$ConfigFilePath       = "C:\DSC\Server2025_Baseline.ps1",
    [string]$BuildDir             = "C:\DSC\Build",
    [string]$PolicyName           = "Audit-Server2025-Baseline"
)

$ErrorActionPreference = 'Stop'

# --- 1. Connect to Azure (Device Code Mode) --------------------------------
Write-Host "Step 1: Connecting to Azure..."
try {
    # Check if already connected
    $null = Get-AzContext -ErrorAction Stop
    Write-Host "Already connected."
}
catch {
    Write-Warning "Please open a browser to https://microsoft.com/devicelogin and enter the code shown below."
    Connect-AzAccount -UseDeviceAuthentication
}

# --- 2. Compile the MOF (Locally) ------------------------------------------
Write-Host "Step 2: Compiling MOF..."

# Clean up build directory
if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
$MofDir = Join-Path $BuildDir "MOF"
New-Item $MofDir -ItemType Directory -Force | Out-Null

# Verify Source Exists
if (-not (Test-Path $ConfigFilePath)) {
    Throw "Configuration file not found at: $ConfigFilePath"
}

# Dot-Source to load the function into memory
. $ConfigFilePath

# Compile
# This creates C:\DSC\Build\MOF\localhost.mof
Server2025_Baseline -NodeName 'localhost' -OutputPath $MofDir

# CRITICAL FIX: Azure Guest Config requires the MOF name to match the Package name.
# We must rename 'localhost.mof' to 'Server2025_Baseline.mof'
$OldMof = Join-Path $MofDir "localhost.mof"
$NewMof = Join-Path $MofDir "Server2025_Baseline.mof"
Rename-Item -Path $OldMof -NewName "Server2025_Baseline.mof" -Force

# --- 3. Create the Guest Configuration Package (.zip) ----------------------
Write-Host "Step 3: Packaging Configuration..."
$PackageDir = Join-Path $BuildDir "Package"
New-Item $PackageDir -ItemType Directory -Force | Out-Null

# This bundles the MOF + Modules into a .zip
$Package = New-GuestConfigurationPackage `
    -Name "Server2025_Baseline" `
    -Configuration $NewMof `
    -Path $PackageDir `
    -Force

# --- 4. Upload to Azure Blob Storage ---------------------------------------
Write-Host "Step 4: Uploading to Azure Storage..."

# Create Container if missing
$Context = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context
if (-not (Get-AzStorageContainer -Name $StorageContainerName -Context $Context -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $StorageContainerName -Context $Context -Permission Blob
}

# Upload
$Blob = Set-AzStorageBlobContent `
    -File $Package.Path `
    -Container $StorageContainerName `
    -Blob "Server2025_Baseline.zip" `
    -Context $Context `
    -Force

# --- 5. Generate SAS Token -------------------------------------------------
Write-Host "Step 5: Generating SAS Token..."
$StartTime = Get-Date
$EndTime = $StartTime.AddYears(3)
$SasToken = New-AzStorageBlobSASToken `
    -Container $StorageContainerName `
    -Blob "Server2025_Baseline.zip" `
    -Permission r `
    -Context $Context `
    -StartTime $StartTime `
    -ExpiryTime $EndTime `
    -FullUri

# --- 6. Create Azure Policy Definition -------------------------------------
Write-Host "Step 6: Creating Azure Policy Definition..."
$PolicyDir = Join-Path $BuildDir "Policy"
New-Item $PolicyDir -ItemType Directory -Force | Out-Null

# Create the Policy files locally
New-GuestConfigurationPolicy `
    -ContentUri $SasToken `
    -DisplayName $PolicyName `
    -Description "Enforces Server 2025 Baseline via Guest Configuration" `
    -Path $PolicyDir `
    -Platform Windows `
    -Mode ApplyAndAutoCorrect `
    -Verbose

# Publish to Azure
$PolicyJson = Get-ChildItem "$PolicyDir\*.json" | Select-Object -First 1
Publish-GuestConfigurationPolicy -Path $PolicyJson.FullName -Verbose

Write-Host "--------------------------------------------------------"
Write-Host "Build Complete!"
Write-Host "1. Go to Azure Portal -> Policy -> Definitions"
Write-Host "2. Search for '$PolicyName'"
Write-Host "3. Assign it to your Arc Servers."
Write-Host "--------------------------------------------------------"
