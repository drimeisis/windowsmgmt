# Build-ManualPackage.ps1

# 1. Compiles MOF in isolation.
# 2. GENERATES Metadata (guestconfiguration.json).
# 3. Zips manually.
# 4. Creates Policy (With explicit PolicyId).

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
$StagingDir = Join-Path $WorkDir "Staging" 

New-Item $ModuleDir -ItemType Directory -Force | Out-Null
New-Item $MofDir -ItemType Directory -Force | Out-Null
New-Item $StagingDir -ItemType Directory -Force | Out-Null

# Download required modules
$Modules = @("SecurityPolicyDsc", "AuditPolicyDsc", "GPRegistryPolicyDsc", "NetworkingDsc")
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

# 1. Copy MOF
Copy-Item "$MofDir\Server2025_Baseline.mof" -Destination $StagingDir

# 2. Copy Modules
$StagingModules = Join-Path $StagingDir "Modules"
New-Item $StagingModules -ItemType Directory -Force | Out-Null

foreach ($m in $Modules) {
    Copy-Item "$ModuleDir\$m" -Destination $StagingModules -Recurse
}

# 3. GENERATE METADATA (guestconfiguration.json)
Write-Host "   [Metadata] Generating guestconfiguration.json..."

$ModuleList = @()
foreach ($m in $Modules) {
    # Get version from the folder name
    $VersionDir = Get-ChildItem "$ModuleDir\$m" | Select-Object -First 1
    if ($VersionDir) {
        $ModuleList += @{ name = $m; version = $VersionDir.Name }
    }
}

$MetaJson = @{
    version = "1.0.0"
    configurationSetting = @{
        configuration = @{
            name = "Server2025_Baseline"
            mofFileName = "Server2025_Baseline.mof"
        }
    }
    modules = $ModuleList
} | ConvertTo-Json -Depth 5

Set-Content -Path "$StagingDir\guestconfiguration.json" -Value $MetaJson -Encoding UTF8

# 4. Zip it
Write-Host "   [Zipping] Creating Server2025_Baseline.zip..."
$ZipPath = Join-Path $WorkDir "Server2025_Baseline.zip"
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipPath -Force

# --- PHASE 5: UPLOAD & PUBLISH ---------------------------------------------
Write-Host "`n--- PHASE 5: Upload & Publish ---" -ForegroundColor Cyan

# 1. Get Storage Key
Write-Host "Fetching Storage Account Keys..."
$Keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$StorageKey = $Keys[0].Value
$StorageCtx = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageKey

# 2. Ensure Container
if (-not (Get-AzStorageContainer -Name $StorageContainerName -Context $StorageCtx -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $StorageContainerName -Context $StorageCtx -Permission Blob
}

# 3. Upload
Write-Host "Uploading to Blob Storage..."
Set-AzStorageBlobContent -File $ZipPath -Container $StorageContainerName -Blob "Server2025_Baseline.zip" -Context $StorageCtx -Force | Out-Null

# 4. SAS Token
$StartTime = Get-Date
$EndTime = $StartTime.AddYears(3)
$SasToken = New-AzStorageBlobSASToken -Container $StorageContainerName -Blob "Server2025_Baseline.zip" -Permission r -Context $StorageCtx -StartTime $StartTime -ExpiryTime $EndTime -FullUri

# 5. Create Policy Definition
Write-Host "Creating Azure Policy Definition..."
$PolicyDir = Join-Path $WorkDir "Policy"
New-Item $PolicyDir -ItemType Directory -Force | Out-Null

# Generate a consistent GUID for the policy ID to satisfy the prompt
$PolicyId = (New-Guid).ToString()

# We use the clean module path for this step
$env:PSModulePath = "$ModuleDir;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
Import-Module GuestConfiguration -Force

# FIX: Added -PolicyId parameter
New-GuestConfigurationPolicy `
    -ContentUri $SasToken `
    -DisplayName $PolicyName `
    -Description "Enforces Server 2025 Baseline via Machine Configuration" `
    -Path $PolicyDir `
    -Platform Windows `
    -Mode ApplyAndAutoCorrect `
    -PolicyId $PolicyId `
    -Verbose

# Restore Module Path
$env:PSModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")

# 6. Publish
$PolicyJson = Get-ChildItem "$PolicyDir\*.json" | Select-Object -First 1
Write-Host "Publishing Policy JSON: $($PolicyJson.Name)..."
Publish-GuestConfigurationPolicy -Path $PolicyJson.FullName -Verbose

Write-Host "`n----------------------------------------------------------------"
Write-Host "SUCCESS! Policy '$PolicyName' created." -ForegroundColor Green
Write-Host "1. Go to Azure Portal > Policy > Definitions."
Write-Host "2. Assign '$PolicyName' to your Arc Servers."
Write-Host "----------------------------------------------------------------"
