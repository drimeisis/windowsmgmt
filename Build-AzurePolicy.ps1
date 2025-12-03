# Build-CleanRoom.ps1
# v4.0 - The "Two-Stage" Clean Room Build
# 
# Fixes "Cannot include more than one version" error by separating 
# Compilation and Packaging into distinct processes.

param(
    [string]$ResourceGroupName    = "demo-rg-arc-gcp",
    [string]$StorageAccountName   = "testacc001010", 
    [string]$StorageContainerName = "dsc-configs",
    [string]$ConfigFilePath       = "C:\DSC\Server2025_Baseline.ps1",
    [string]$WorkDir              = "C:\DSC\CleanBuild",
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
Write-Host "`n--- PHASE 2: Preparing Clean Room ---" -ForegroundColor Cyan

if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
$ModuleDir  = Join-Path $WorkDir "Modules"
$MofDir     = Join-Path $WorkDir "MOF"
$PkgDir     = Join-Path $WorkDir "Package"

New-Item $ModuleDir -ItemType Directory -Force | Out-Null
New-Item $MofDir -ItemType Directory -Force | Out-Null
New-Item $PkgDir -ItemType Directory -Force | Out-Null

# Download fresh modules
$Modules = @("GuestConfiguration", "SecurityPolicyDsc", "AuditPolicyDsc", "GPRegistryPolicyDsc", "NetworkingDsc")
foreach ($m in $Modules) {
    Write-Host "Downloading $m..."
    Save-Module -Name $m -Path $ModuleDir -Force -ErrorAction Stop
}

# --- PHASE 3: WORKER 1 (COMPILER) ------------------------------------------
Write-Host "`n--- PHASE 3: Compilation (Worker 1) ---" -ForegroundColor Cyan

$CompilerScript = Join-Path $WorkDir "Worker_Compile.ps1"
$CompilerCode = @"
    `$ErrorActionPreference = 'Stop'
    `$env:PSModulePath = "$ModuleDir;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
    
    Write-Host "   [Compiler] Compiling MOF..."
    
    # Dot-Source Config
    . "$ConfigFilePath"
    
    # Compile
    Server2025_Baseline -NodeName 'localhost' -OutputPath "$MofDir"
    
    # Rename
    `$Old = Join-Path "$MofDir" "localhost.mof"
    `$New = Join-Path "$MofDir" "Server2025_Baseline.mof"
    Rename-Item -Path `$Old -NewName "Server2025_Baseline.mof" -Force
    
    Write-Host "   [Compiler] Done."
"@
Set-Content -Path $CompilerScript -Value $CompilerCode

$Proc1 = Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass", "-File `"$CompilerScript`"" -Wait -NoNewWindow -PassThru
if ($Proc1.ExitCode -ne 0) { Throw "Compilation failed." }


# --- PHASE 4: WORKER 2 (PACKAGER) ------------------------------------------
Write-Host "`n--- PHASE 4: Packaging (Worker 2) ---" -ForegroundColor Cyan
# This worker runs in a FRESH process. It sees the modules on disk, 
# but DOES NOT have them loaded in memory, preventing the version conflict bug.

$PackagerScript = Join-Path $WorkDir "Worker_Package.ps1"
$PackagerCode = @"
    `$ErrorActionPreference = 'Stop'
    `$env:PSModulePath = "$ModuleDir;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
    
    Write-Host "   [Packager] Loading GuestConfiguration..."
    Import-Module GuestConfiguration -Force
    
    Write-Host "   [Packager] Zipping Package..."
    # Points to the MOF created by Worker 1
    `$MofPath = "$MofDir\Server2025_Baseline.mof"
    
    New-GuestConfigurationPackage -Name "Server2025_Baseline" -Configuration `$MofPath -Path "$PkgDir" -Force
    
    Write-Host "   [Packager] Done."
"@
Set-Content -Path $PackagerScript -Value $PackagerCode

$Proc2 = Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass", "-File `"$PackagerScript`"" -Wait -NoNewWindow -PassThru
if ($Proc2.ExitCode -ne 0) { Throw "Packaging failed." }

# Verify
$ZipPath = Join-Path $PkgDir "Server2025_Baseline.zip"
if (-not (Test-Path $ZipPath)) { Throw "Package zip not found." }

# --- PHASE 5: UPLOAD & PUBLISH ---------------------------------------------
Write-Host "`n--- PHASE 5: Upload & Publish ---" -ForegroundColor Cyan

Write-Host "Uploading to $StorageAccountName..."
if (-not (Get-AzStorageContainer -Name $StorageContainerName -Context $AzContext.Context -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $StorageContainerName -Context $AzContext.Context -Permission Blob
}

Set-AzStorageBlobContent -File $ZipPath -Container $StorageContainerName -Blob "Server2025_Baseline.zip" -Context $AzContext.Context -Force | Out-Null

Write-Host "Generating SAS Token..."
$StartTime = Get-Date
$EndTime = $StartTime.AddYears(3)
$SasToken = New-AzStorageBlobSASToken -Container $StorageContainerName -Blob "Server2025_Baseline.zip" -Permission r -Context $AzContext.Context -StartTime $StartTime -ExpiryTime $EndTime -FullUri

Write-Host "Publishing Policy..."
$PolicyDir = Join-Path $WorkDir "Policy"
New-Item $PolicyDir -ItemType Directory -Force | Out-Null

New-GuestConfigurationPolicy `
    -ContentUri $SasToken `
    -DisplayName $PolicyName `
    -Description "Enforces Server 2025 Baseline" `
    -Path $PolicyDir `
    -Platform Windows `
    -Mode ApplyAndAutoCorrect `
    -Verbose

$PolicyJson = Get-ChildItem "$PolicyDir\*.json" | Select-Object -First 1
Publish-GuestConfigurationPolicy -Path $PolicyJson.FullName -Verbose

Write-Host "`nSUCCESS! Policy '$PolicyName' is published." -ForegroundColor Green
