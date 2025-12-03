# Build-ManualPackage.ps1
# 1. Compiles MOF in isolation.
# 2. MANUALLY constructs the Azure Guest Configuration Zip structure.
# 3. Uploads and creates Policy using manually calculated Hash.

param(
    [string]$ResourceGroupName    = "demo-rg-arc-gcp",
    [string]$StorageAccountName   = "testacc001010", 
    [string]$StorageContainerName = "dsc-configs",
    [string]$ConfigFilePath       = "C:\DSC\Server2025_Baseline.ps1",
    [string]$WorkDir              = "C:\DSC\ManualBuild",
    [string]$PolicyName           = "Audit-Server2025-Baseline"
)

$ErrorActionPreference = 'Stop'

# --- PHASE 1: AZURE LOGIN --------------------------------------------------
Write-Host "--- PHASE 1: Azure Authentication ---" -ForegroundColor Cyan

function Assert-AzureLogin {
    $Ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $Ctx) {
        Write-Warning "No Azure Context found. Initiating Device Login..."
        Write-Warning ">> OPEN BROWSER TO: https://microsoft.com/devicelogin <<"
        Connect-AzAccount -UseDeviceAuthentication
        $Ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $Ctx) { Throw "CRITICAL: Login failed." }
    }
    Write-Host "Connected as: $($Ctx.Account.Id)" -ForegroundColor Green
    return $Ctx
}
$AzContext = Assert-AzureLogin

# --- PHASE 2: PREPARE FILES ------------------------------------------------
Write-Host "`n--- PHASE 2: Preparing Workspace ---" -ForegroundColor Cyan

if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
$ModuleDir  = Join-Path $WorkDir "Modules"
$MofDir     = Join-Path $WorkDir "MOF"
$StagingDir = Join-Path $WorkDir "Staging" # Where we build the zip content

New-Item $ModuleDir -ItemType Directory -Force | Out-Null
New-Item $MofDir -ItemType Directory -Force | Out-Null
New-Item $StagingDir -ItemType Directory -Force | Out-Null

# Download required modules (We need these for compilation AND for the zip)
$Modules = @("SecurityPolicyDsc", "AuditPolicyDsc", "GPRegistryPolicyDsc", "NetworkingDsc")

# Also need GuestConfig for the Policy step later, but not for the zip
Save-Module -Name "GuestConfiguration" -Path $ModuleDir -Force -ErrorAction Stop

foreach ($m in $Modules) {
    Write-Host "Downloading $m..."
    Save-Module -Name $m -Path $ModuleDir -Force -ErrorAction Stop
}

# --- PHASE 3: COMPILE MOF (Worker) -----------------------------------------
Write-Host "`n--- PHASE 3: Compiling MOF ---" -ForegroundColor Cyan

$CompilerScript = Join-Path $WorkDir "Worker_Compile.ps1"
$CompilerCode = @"
    `$ErrorActionPreference = 'Stop'
    `$env:PSModulePath = "$ModuleDir;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
    
    Write-Host "   [Compiler] Compiling..."
    . "$ConfigFilePath"
    Server2025_Baseline -NodeName 'localhost' -OutputPath "$MofDir"
    
    `$Old = Join-Path "$MofDir" "localhost.mof"
    `$New = Join-Path "$MofDir" "Server2025_Baseline.mof"
    Rename-Item -Path `$Old -NewName "Server2025_Baseline.mof" -Force
"@
Set-Content -Path $CompilerScript -Value $CompilerCode

$Proc = Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass", "-File `"$CompilerScript`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Compilation failed." }

if (-not (Test-Path "$MofDir\Server2025_Baseline.mof")) { Throw "MOF file missing." }

# --- PHASE 4: MANUAL PACKAGE ASSEMBLY --------------------------------------
Write-Host "`n--- PHASE 4: Manually Building Package ---" -ForegroundColor Cyan
# Instead of using New-GuestConfigurationPackage, we build the folder structure ourselves.
# Structure:
#   Root/
#     Server2025_Baseline.mof
#     Modules/
#       ModuleA/Version/...
#       ModuleB/Version/...

# 1. Copy MOF
Copy-Item "$MofDir\Server2025_Baseline.mof" -Destination $StagingDir

# 2. Copy Modules
$StagingModules = Join-Path $StagingDir "Modules"
New-Item $StagingModules -ItemType Directory -Force | Out-Null

foreach ($m in $Modules) {
    # We copy the full version folder from our clean download
    # Source: C:\DSC\Clean\Modules\SecurityPolicyDsc
    # Dest:   C:\DSC\Clean\Staging\Modules\SecurityPolicyDsc
    Copy-Item "$ModuleDir\$m" -Destination $StagingModules -Recurse
}

# 3. Zip it
Write-Host "   [Zipping] Creating Server2025_Baseline.zip..."
$ZipPath = Join-Path $WorkDir "Server2025_Baseline.zip"
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipPath -Force

# 4. Calculate Hash (Required for Policy)
$HashObj = Get-FileHash -Path $ZipPath -Algorithm SHA256
$ContentHash = $HashObj.Hash
Write-Host "   [Hash] SHA256: $ContentHash" -ForegroundColor Yellow

# --- PHASE 5: UPLOAD & PUBLISH ---------------------------------------------
Write-Host "`n--- PHASE 5: Upload & Publish ---" -ForegroundColor Cyan

# Ensure Container
if (-not (Get-AzStorageContainer -Name $StorageContainerName -Context $AzContext.Context -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $StorageContainerName -Context $AzContext.Context -Permission Blob
}

# Upload
Write-Host "Uploading to Blob Storage..."
Set-AzStorageBlobContent -File $ZipPath -Container $StorageContainerName -Blob "Server2025_Baseline.zip" -Context $AzContext.Context -Force | Out-Null

# SAS Token
$StartTime = Get-Date
$EndTime = $StartTime.AddYears(3)
$SasToken = New-AzStorageBlobSASToken -Container $StorageContainerName -Blob "Server2025_Baseline.zip" -Permission r -Context $AzContext.Context -StartTime $StartTime -ExpiryTime $EndTime -FullUri

# Create Policy Definition
Write-Host "Creating Azure Policy Definition..."
$PolicyDir = Join-Path $WorkDir "Policy"
New-Item $PolicyDir -ItemType Directory -Force | Out-Null

# We use the GuestConfiguration module ONLY for this step (Policy JSON generation).
# We pass it the SAS Token and the manually calculated Hash.
# We explicitly set PSModulePath to use our clean module download to avoid conflicts.
$env:PSModulePath = "$ModuleDir;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
Import-Module GuestConfiguration -Force

New-GuestConfigurationPolicy `
    -ContentUri $SasToken `
    -ContentHash $ContentHash `
    -DisplayName $PolicyName `
    -Description "Enforces Server 2025 Baseline via Machine Configuration" `
    -Path $PolicyDir `
    -Platform Windows `
    -Mode ApplyAndAutoCorrect `
    -Verbose

# Restore Module Path (Good Practice)
$env:PSModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")

# Publish
$PolicyJson = Get-ChildItem "$PolicyDir\*.json" | Select-Object -First 1
Write-Host "Publishing Policy JSON: $($PolicyJson.Name)..."
Publish-GuestConfigurationPolicy -Path $PolicyJson.FullName -Verbose

Write-Host "`n----------------------------------------------------------------"
Write-Host "SUCCESS! Policy '$PolicyName' created successfully." -ForegroundColor Green
Write-Host "You successfully bypassed the buggy packager."
Write-Host "1. Go to Azure Portal > Policy > Definitions."
Write-Host "2. Assign '$PolicyName' to your Arc Servers."
Write-Host "----------------------------------------------------------------"
