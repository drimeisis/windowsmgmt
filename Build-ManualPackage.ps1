# Build-ManualPackage.ps1

# 1. Compiles MOF in isolation.
# 2. Generates Metadata & Zips manually.
# 3. Creates & Publishes Policy (Fixes Pathing & Version parameters).

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
# Also need GuestConfig for the Policy step
Save-Module -Name "GuestConfiguration" -Path $ModuleDir -Force -ErrorAction Stop

foreach ($m in $Modules) {
    Write-Host "Downloading $m..."
    Save-Module -Name $m -Path $ModuleDir -Force -ErrorAction Stop
}

# --- PHASE 3: COMPILE MOF (Worker) -----------------------------------------
Write-Host "`n--- PHASE 3: Compiling MOF ---" -ForegroundColor Cyan

$CompilerScript = Join-Path $WorkDir "Worker_Compile.ps1"
# We use a Here-String for the worker code.
# IMPORTANT: The closing "@" must be the very first character on the line.
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

# 3. GENERATE METADATA
Write-Host "   [Metadata] Generating guestconfiguration.json..."
$ModuleList = @()
foreach ($m in $Modules) {
    $VersionDir = Get-ChildItem "$ModuleDir\$m" | Select-Object -First 1
    if ($VersionDir) { $ModuleList += @{ name = $m; version = $VersionDir.Name } }
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

# 4. Zip
Write-Host "   [Zipping] Creating Server2025_Baseline.zip..."
$ZipPath = Join-Path $WorkDir "Server2025_Baseline.zip"
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipPath -Force

# 5. Calculate Hash
$HashObj = Get-FileHash -Path $ZipPath -Algorithm SHA256
$ContentHash = $HashObj.Hash
Write-Host "   [Hash] SHA256: $ContentHash" -ForegroundColor Yellow

# --- PHASE 5: UPLOAD & PUBLISH ---------------------------------------------
Write-Host "`n--- PHASE 5: Upload & Publish ---" -ForegroundColor Cyan

# 1. Storage Keys
Write-Host "Fetching Storage Account Keys..."
$Keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$StorageCtx = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $Keys[0].Value

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

# 5. Create Policy Definition using SPLATTING
Write-Host "Creating Azure Policy Definition..."
$PolicyDir = Join-Path $WorkDir "Policy"
New-Item $PolicyDir -ItemType Directory -Force | Out-Null

# Set path to our downloaded modules so GuestConfiguration loads correctly
$env:PSModulePath = "$ModuleDir;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
Import-Module GuestConfiguration -Force

$PolicyParams = @{
    ContentUri      = $SasToken
    DisplayName     = $PolicyName
    Description     = "Enforces Server 2025 Baseline via Machine Configuration"
    Path            = $PolicyDir
    Platform        = "Windows"
    Mode            = "ApplyAndAutoCorrect"
    PolicyVersion   = "1.0.0"               # FIX: Added required Version
    PolicyId        = (New-Guid).ToString() # FIX: Added required GUID
    Verbose         = $true
}

# Check if this version supports ContentHash (some do, some don't)
if (Get-Help New-GuestConfigurationPolicy -Parameter ContentHash -ErrorAction SilentlyContinue) {
    $PolicyParams['ContentHash'] = $ContentHash
}

# Execute
New-GuestConfigurationPolicy @PolicyParams

# 6. Publish
$PolicyJson = Get-ChildItem "$PolicyDir\*.json" | Select-Object -First 1
Write-Host "Publishing Policy JSON: $($PolicyJson.Name)..."

# Ensure the module is still loaded and command is available
if (-not (Get-Command Publish-GuestConfigurationPolicy -ErrorAction SilentlyContinue)) {
    Import-Module GuestConfiguration -Force
}

Publish-GuestConfigurationPolicy -Path $PolicyJson.FullName -Verbose

# 7. Restore Module Path (ONLY AFTER EVERYTHING IS DONE)
$env:PSModulePath = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")

Write-Host "`n----------------------------------------------------------------"
Write-Host "SUCCESS! Policy '$PolicyName' created." -ForegroundColor Green
Write-Host "1. Go to Azure Portal > Policy > Definitions."
Write-Host "2. Assign '$PolicyName' to your Arc Servers."
Write-Host "----------------------------------------------------------------"
